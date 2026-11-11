package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/GarlandQian/cpa-plugin-veil/internal/mask"
	"github.com/GarlandQian/cpa-plugin-veil/internal/records"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// pluginRuntime admits calls into one instance. Registration and reconfigure
// serialize with disposal; ordinary calls keep the policy view they began
// with. Only native init creates a replacement runtime after shutdown.
type pluginRuntime struct {
	mu        sync.Mutex
	configure sync.Mutex
	once      sync.Once
	closed    bool
	inFlight  sync.WaitGroup
	instance  *pluginInstance
	plugin    *veilPlugin
}

func (r *pluginRuntime) begin() (*veilPlugin, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, nil, fmt.Errorf("veil plugin is shutting down")
	}
	if r.plugin == nil {
		return nil, nil, fmt.Errorf("veil plugin is not registered")
	}
	r.inFlight.Add(1)
	return r.plugin, r.inFlight.Done, nil
}

func (r *pluginRuntime) close() {
	r.once.Do(func() {
		// Shut admission before waiting for a config build or any active call.
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.configure.Lock()
		defer r.configure.Unlock()
		r.inFlight.Wait()
		if r.instance != nil {
			r.instance.close()
		}
		r.mu.Lock()
		r.plugin, r.instance = nil, nil
		r.mu.Unlock()
	})
}

func (r *pluginRuntime) register(ctx context.Context, method string, request []byte) ([]byte, error) {
	r.configure.Lock()
	defer r.configure.Unlock()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("veil plugin is shutting down")
	}
	if r.instance == nil {
		r.instance = &pluginInstance{}
	}
	previous, instance := r.plugin, r.instance
	r.mu.Unlock()
	var req abiLifecycleRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	plugin, err := instance.configure(req.ConfigYAML, req.PluginDir)
	// A close that began during construction wins, even if the build failed.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("veil plugin is shutting down")
	}
	if err != nil {
		r.mu.Unlock()
		// CPA drops a plugin whose reconfigure fails. Keep masking with the
		// previous valid view and make the rejected config visible in the log.
		if method == pluginabi.MethodPluginReconfigure && previous != nil {
			pluginLog(ctx, logLevelError, "veil rejected new config, still using the previous valid config: "+err.Error(), map[string]any{"error": err.Error()})
			return abiOKEnvelope(newABIRegistration(pluginMetadata(), req.SchemaVersion))
		}
		return nil, err
	}
	plugin.hostTooOld = hostTooOld(req.SchemaVersion)
	r.plugin = plugin
	r.mu.Unlock()
	if plugin.hostTooOld != "" {
		pluginLog(ctx, logLevelError, "veil will stop every request: "+plugin.hostTooOld, nil)
	}
	return abiOKEnvelope(newABIRegistration(pluginMetadata(), req.SchemaVersion))
}

// answer is the Host seam: it takes a call of the Host and always returns the
// envelope to send back. The Host keeps the original body after a failure
// answer to a request hook, so a request hook never gets one (ADR-0002); any
// other hook's failure leaves the Host's response as it is, Placeholders and
// all. A nil runtime is one the Host has not started or has shut down.
func (r *pluginRuntime) answer(ctx context.Context, method string, request []byte) []byte {
	err := errNotInitialized
	if r != nil {
		var out []byte
		if out, err = r.handle(ctx, method, request); err == nil {
			return out
		}
	}
	if method == pluginabi.MethodRequestInterceptBefore || method == pluginabi.MethodRequestInterceptAfter {
		return r.stopUnmasked(ctx, method, request, err)
	}
	return abiErrorEnvelope("plugin_error", err.Error())
}

var errNotInitialized = errors.New("veil plugin is not initialized")

// stopUnmasked answers a request hook that could not run with a Stopped
// request, keeping what it can of a call it can read. A live instance also
// records it, so a Host that hands Veil calls it cannot read shows on the
// records page as well as in the log.
func (r *pluginRuntime) stopUnmasked(ctx context.Context, method string, request []byte, cause error) (out []byte) {
	defer func() {
		if recover() != nil {
			out, _ = abiOKEnvelope(stoppedAnswer("", nil, stoppedUnreadable))
		}
	}()
	start := time.Now()
	req, err := readRequestCall(request)
	if err != nil {
		cause = err
	} else if len(req.Body) == 0 {
		out, _ = abiOKEnvelope(abiRequestInterceptResponse{})
		return out
	}
	if r != nil {
		if p, done, err := r.begin(); err == nil {
			defer done()
			p.record(req, mask.Report{}, records.StoppedError, start)
		}
	}
	out, _ = abiOKEnvelope(stop(withHostCallbackID(ctx, req.HostCallbackID), req, method+": "+cause.Error(), stoppedUnreadable))
	return out
}

// readRequestCall decodes a request hook's call. The Host always names the
// Body, null when there is none, so a call that does not is no request with
// nothing to mask but a Host that calls the field something else.
func readRequestCall(request []byte) (abiRequestInterceptRequest, error) {
	var req abiRequestInterceptRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return abiRequestInterceptRequest{}, errors.New("the call cannot be read: " + decodeFailure(err))
	}
	if len(req.Body) > 0 {
		return req, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(request, &fields); err != nil {
		return abiRequestInterceptRequest{}, errors.New("the call cannot be read: " + decodeFailure(err))
	}
	for name := range fields {
		if strings.EqualFold(name, "Body") {
			return req, nil
		}
	}
	return abiRequestInterceptRequest{}, errors.New("the call has no Body field")
}

// decodeFailure says why a call did not decode without quoting it: a JSON
// error can carry the value it could not place.
func decodeFailure(err error) string {
	var wrongType *json.UnmarshalTypeError
	if errors.As(err, &wrongType) {
		return fmt.Sprintf("field %q is not a %s", wrongType.Field, wrongType.Type)
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return fmt.Sprintf("it stops being JSON at byte %d", syntax.Offset)
	}
	return "it is not JSON"
}

func (r *pluginRuntime) handle(ctx context.Context, method string, request []byte) (out []byte, err error) {
	// A panic must not cross into the host: it would take the whole process
	// down. Request interceptors recover on their own and stop the request.
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("veil %s panicked: %v", method, r)
		}
	}()
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return r.register(ctx, method, request)
	}

	p, done, errPlugin := r.begin()
	if errPlugin != nil {
		return nil, errPlugin
	}
	defer done()

	switch method {
	case pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter:
		req, errDecode := readRequestCall(request)
		if errDecode != nil {
			return nil, errDecode
		}
		return abiOKEnvelope(p.interceptRequest(withHostCallbackID(ctx, req.HostCallbackID), req))
	case pluginabi.MethodResponseInterceptAfter:
		var req abiResponseInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		return abiOKEnvelope(p.interceptResponse(withHostCallbackID(ctx, req.HostCallbackID), req))
	case pluginabi.MethodResponseInterceptStreamChunk:
		var req abiStreamChunkInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		return abiOKEnvelope(p.interceptStreamChunk(withHostCallbackID(ctx, req.HostCallbackID), req))
	case pluginabi.MethodManagementRegister:
		var req pluginapi.ManagementRegistrationRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		return abiOKEnvelope(managementRoutes(req.ResourceBasePath))
	case pluginabi.MethodManagementHandle:
		var req abiManagementRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		return abiOKEnvelope(p.handleManagement(req.ManagementRequest))
	default:
		return abiErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}
