package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

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
	r.plugin = plugin.Capabilities.RequestInterceptor.(*veilPlugin)
	r.mu.Unlock()
	return abiOKEnvelope(newABIRegistration(plugin.Metadata, req.SchemaVersion))
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
	case pluginabi.MethodRequestInterceptBefore:
		var req abiRequestInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.interceptRequest(withHostCallbackID(ctx, req.HostCallbackID), req.RequestInterceptRequest, req.RequestID, false)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodRequestInterceptAfter:
		var req abiRequestInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.interceptRequest(withHostCallbackID(ctx, req.HostCallbackID), req.RequestInterceptRequest, req.RequestID, true)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodResponseInterceptAfter:
		var req abiResponseInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.interceptResponse(withHostCallbackID(ctx, req.HostCallbackID), req.ResponseInterceptRequest, req.RequestID)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodResponseInterceptStreamChunk:
		var req abiStreamChunkInterceptRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.interceptStreamChunk(withHostCallbackID(ctx, req.HostCallbackID), req.StreamChunkInterceptRequest, req.RequestID)
		return abiOKEnvelopeWithError(resp, errCall)
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
