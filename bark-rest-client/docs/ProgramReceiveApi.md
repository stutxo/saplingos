# \ProgramReceiveApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**commit**](ProgramReceiveApi.md#commit) | **POST** /api/v1/receive/program/commit | Commit a program receive
[**prepare**](ProgramReceiveApi.md#prepare) | **POST** /api/v1/receive/program/prepare | Prepare a program receive



## commit

> serde_json::Value commit(receive_request)
Commit a program receive

Accepts only complete signed VTXOs whose exact recovery claims were already prepared. Verifies the complete chain, durably merges signed ancestors, and stores the received position before it acknowledges delivery. Returns a U-signed acknowledgement over the final signed VTXO bytes. The sender must checkpoint those bytes before calling this endpoint and must retry exactly those bytes after interruption. No new Sapio signature is requested. Requests are limited to 1 MiB and 16 VTXOs. This endpoint exists only on the configured receiving-only listener.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**receive_request** | [**ReceiveRequest**](ReceiveRequest.md) |  | [required] |

### Return type

[**serde_json::Value**](serde_json::Value.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## prepare

> serde_json::Value prepare(receive_request)
Prepare a program receive

Validates unsigned candidate VTXOs for a stored program address and durably saves authorized recovery claims. Returns a versioned receipt with address, candidate encodings, ProgramKey descriptor, recovery records and a U signature. The sender must verify the descriptor aggregates U and S to the address key, each claim, and the receipt signature before it signs its inputs. Requests are limited to 1 MiB and 16 VTXOs. Each address admits at most 128 distinct prepared outputs. This endpoint exists only on the configured receiving-only listener; it does not grant administrative authority.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**receive_request** | [**ReceiveRequest**](ReceiveRequest.md) |  | [required] |

### Return type

[**serde_json::Value**](serde_json::Value.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

