package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int VeilPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void VeilPluginFree(void*, size_t);
extern void VeilPluginShutdown(void);

static int veil_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}

static void veil_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var veilABIState = struct {
	sync.RWMutex
	host      *C.cliproxy_host_api
	runtime   *pluginRuntime
	lifecycle sync.Mutex // serializes native init and shutdown
}{}

const maxCGoBytesLen = C.size_t(1<<31 - 1)

type abiEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *abiError       `json:"error,omitempty"`
}

type abiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type abiLifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
	PluginDir  string `json:"plugin_dir,omitempty"`
	// SchemaVersion is the host's; CPA v7 sends none.
	SchemaVersion uint32 `json:"schema_version,omitempty"`
}

type abiRequestInterceptRequest struct {
	pluginapi.RequestInterceptRequest
	// RequestID is provided by CPA v8; the v7 SDK predates it.
	RequestID      string `json:"RequestID,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiResponseInterceptRequest struct {
	pluginapi.ResponseInterceptRequest
	// Preserve the same ID used by the request hook, including across reloads.
	RequestID      string `json:"RequestID,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiStreamChunkInterceptRequest struct {
	pluginapi.StreamChunkInterceptRequest
	// RequestID is the request's own ID, which CPA v8 gives every chunk of
	// its stream; the SDK Veil builds with predates it.
	RequestID      string `json:"RequestID,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  abiCapabilities    `json:"capabilities"`
}

type abiCapabilities struct {
	RequestInterceptor     bool `json:"request_interceptor"`
	ResponseInterceptor    bool `json:"response_interceptor"`
	StreamChunkInterceptor bool `json:"response_stream_interceptor"`
	ManagementAPI          bool `json:"management_api"`
}

type abiHostLogRequest struct {
	HostCallbackID string         `json:"host_callback_id,omitempty"`
	Level          string         `json:"level"`
	Message        string         `json:"message"`
	Fields         map[string]any `json:"fields,omitempty"`
}

const (
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
)

type hostCallbackIDKey struct{}

func withHostCallbackID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if id = strings.TrimSpace(id); id == "" {
		return ctx
	}
	return context.WithValue(ctx, hostCallbackIDKey{}, id)
}

func hostCallbackIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(hostCallbackIDKey{}).(string)
	return id
}

// pluginLog routes logs through host.log so they follow the host's log level,
// format and output and carry the request_id. The plugin's own logrus copy is
// a separate instance inside the shared library, so it is only a fallback for
// when no host is attached (tests, or a failed host call).
func pluginLog(ctx context.Context, level, message string, fields map[string]any) {
	if hostLog(hostCallbackIDFromContext(ctx), level, message, fields) {
		return
	}
	entry := log.WithFields(log.Fields(fields))
	switch level {
	case logLevelError:
		entry.Error(message)
	case logLevelWarn:
		entry.Warn(message)
	case logLevelInfo:
		entry.Info(message)
	default:
		entry.Debug(message)
	}
}

func hostLog(callbackID, level, message string, fields map[string]any) bool {
	veilABIState.RLock()
	host := veilABIState.host
	veilABIState.RUnlock()
	if host == nil || host.call == nil {
		return false
	}
	raw, errMarshal := json.Marshal(abiHostLogRequest{
		HostCallbackID: callbackID,
		Level:          level,
		Message:        message,
		Fields:         fields,
	})
	if errMarshal != nil {
		return false
	}

	method := C.CString(pluginabi.MethodHostLog)
	defer C.free(unsafe.Pointer(method))
	request := C.CBytes(raw)
	defer C.free(request)

	var response C.cliproxy_buffer
	status := C.veil_call_host(host, method, (*C.uint8_t)(request), C.size_t(len(raw)), &response)
	if response.ptr != nil && host.free_buffer != nil {
		defer C.veil_free_host_buffer(host, response.ptr, response.len)
	}
	if status != 0 {
		return false
	}
	if response.ptr == nil || response.len == 0 || response.len > maxCGoBytesLen {
		return true
	}
	var envelope abiEnvelope
	if errDecode := json.Unmarshal(C.GoBytes(response.ptr, C.int(response.len)), &envelope); errDecode != nil {
		return false
	}
	return envelope.OK
}

func main() {}

func inferPluginDir() string {
	sharedObjectPath := sharedLibraryPath()
	if sharedObjectPath == "" {
		return ""
	}
	return filepath.Dir(sharedObjectPath)
}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	veilABIState.lifecycle.Lock()
	defer veilABIState.lifecycle.Unlock()
	veilABIState.RLock()
	previous := veilABIState.runtime
	veilABIState.RUnlock()
	if previous != nil {
		previous.close()
	}
	veilABIState.Lock()
	veilABIState.host = host
	veilABIState.runtime = &pluginRuntime{}
	veilABIState.Unlock()

	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.VeilPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.VeilPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.VeilPluginShutdown)
	return 0
}

//export VeilPluginCall
func VeilPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeABIResponse(response, abiErrorEnvelope("invalid_method", "method is required"))
		return 0
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		if requestLen > maxCGoBytesLen {
			writeABIResponse(response, abiErrorEnvelope("request_too_large", "request payload is too large"))
			return 0
		}
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleVeilABIMethod(context.Background(), C.GoString(method), requestBytes)
	if errHandle != nil {
		writeABIResponse(response, abiErrorEnvelope("plugin_error", errHandle.Error()))
		return 0
	}
	writeABIResponse(response, raw)
	return 0
}

//export VeilPluginFree
func VeilPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export VeilPluginShutdown
func VeilPluginShutdown() {
	veilABIState.lifecycle.Lock()
	defer veilABIState.lifecycle.Unlock()
	veilABIState.RLock()
	runtime := veilABIState.runtime
	veilABIState.RUnlock()
	if runtime != nil {
		runtime.close()
	}
	veilABIState.Lock()
	veilABIState.runtime, veilABIState.host = nil, nil
	veilABIState.Unlock()
}

func handleVeilABIMethod(ctx context.Context, method string, request []byte) ([]byte, error) {
	veilABIState.RLock()
	runtime := veilABIState.runtime
	veilABIState.RUnlock()
	if runtime == nil {
		return nil, fmt.Errorf("veil plugin is not initialized")
	}
	return runtime.handle(ctx, method, request)
}

// veilSchemaVersion is the plugin schema Veil speaks where the host does
// too. From 3 on, a stream's payload chunks come without the request bodies
// and from 5 on without the chunks before them, which a host otherwise
// copies and encodes into every chunk, megabytes each for an agent's long
// history; Veil knows a stream by its request ID instead. From 6 on CPA
// would stop escaping management answers, which the records page undoes.
const veilSchemaVersion = 5

// schemaOmittingStreamBodies is the first schema whose payload chunks come
// without the request bodies.
const schemaOmittingStreamBodies = 3

// schemaFor is the schema Veil registers with on a host that offers host:
// the original one on a host that offers none (CPA v7) or one that still
// sends every chunk its request bodies.
func schemaFor(host uint32) uint32 {
	if host < schemaOmittingStreamBodies {
		return pluginabi.SchemaVersion
	}
	return min(host, veilSchemaVersion)
}

func newABIRegistration(metadata pluginapi.Metadata, hostSchema uint32) abiRegistration {
	return abiRegistration{
		SchemaVersion: schemaFor(hostSchema),
		Metadata:      metadata,
		Capabilities:  abiCapabilities{RequestInterceptor: true, ResponseInterceptor: true, StreamChunkInterceptor: true, ManagementAPI: true},
	}
}

func abiOKEnvelopeWithError(v any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return abiOKEnvelope(v)
}

func abiOKEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(abiEnvelope{OK: true, Result: raw})
}

func abiErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(abiEnvelope{OK: false, Error: &abiError{Code: code, Message: message}})
	return raw
}

func writeABIResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
