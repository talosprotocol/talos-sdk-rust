use futures_core::Stream;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use serde_json::{json, Map, Value};
use std::pin::Pin;
use std::time::Duration;
use thiserror::Error;

pub const TALOS_ATTESTATION_EXTENSION: &str =
    "https://talosprotocol.com/extensions/a2a/attestation/v1";
pub const TALOS_SECURE_CHANNELS_EXTENSION: &str =
    "https://talosprotocol.com/extensions/a2a/secure-channels/v1";
pub const TALOS_COMPAT_JSONRPC_EXTENSION: &str =
    "https://talosprotocol.com/extensions/a2a/compat-jsonrpc/v0";

#[derive(Error, Debug)]
pub enum A2AError {
    #[error("HTTP {status_code}: {payload}")]
    HttpStatus { status_code: u16, payload: String },
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("unexpected A2A payload: {0}")]
    UnexpectedPayload(String),
}

#[derive(Clone, Default)]
pub struct A2AMessageOptions {
    pub message_id: Option<String>,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    pub configuration: Option<Value>,
    pub metadata: Option<Value>,
}

#[derive(Clone, Default)]
pub struct A2ATaskOptions {
    pub history_length: Option<u64>,
    pub include_artifacts: bool,
}

#[derive(Clone, Default)]
pub struct A2AListTasksOptions {
    pub context_id: Option<String>,
    pub status: Option<String>,
    pub page_size: Option<u64>,
    pub page_token: Option<String>,
    pub history_length: Option<u64>,
    pub include_artifacts: bool,
}

#[derive(Clone)]
pub struct A2APushNotificationConfigOptions {
    pub url: String,
    pub token: Option<String>,
    pub authentication: Option<Value>,
    pub config_id: Option<String>,
}

#[derive(Clone)]
pub struct A2AJsonRpcClient {
    base_url: String,
    api_token: Option<String>,
    http: Client,
}

pub type A2AEventStream = Pin<Box<dyn Stream<Item = Result<Value, A2AError>> + Send>>;

impl A2AJsonRpcClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_token: None,
            http,
        }
    }

    pub fn with_api_token(mut self, api_token: impl Into<String>) -> Self {
        self.api_token = Some(api_token.into());
        self
    }

    pub async fn get_agent_card(&self) -> Result<Value, A2AError> {
        self.request_json(
            self.http
                .get(format!("{}/.well-known/agent-card.json", self.base_url)),
        )
        .await
    }

    pub async fn get_extended_agent_card(&self) -> Result<Value, A2AError> {
        self.request_json(
            self.http
                .get(format!("{}/extendedAgentCard", self.base_url)),
        )
        .await
    }

    pub async fn get_authenticated_extended_agent_card(&self) -> Result<Value, A2AError> {
        self.rpc("GetExtendedAgentCard", json!({})).await
    }

    pub async fn send_message(
        &self,
        text: &str,
        options: A2AMessageOptions,
    ) -> Result<Value, A2AError> {
        let mut params = Map::new();
        params.insert("message".to_string(), self.message(text, &options));
        if let Some(configuration) = options.configuration {
            params.insert("configuration".to_string(), configuration);
        }
        self.rpc("SendMessage", Value::Object(params)).await
    }

    pub async fn send_streaming_message(
        &self,
        text: &str,
        options: A2AMessageOptions,
    ) -> Result<Vec<Value>, A2AError> {
        let mut params = Map::new();
        params.insert("message".to_string(), self.message(text, &options));
        if let Some(configuration) = options.configuration {
            params.insert("configuration".to_string(), configuration);
        }
        self.stream("SendStreamingMessage", Value::Object(params))
            .await
    }

    pub async fn send_streaming_message_events(
        &self,
        text: &str,
        options: A2AMessageOptions,
    ) -> Result<A2AEventStream, A2AError> {
        let mut params = Map::new();
        params.insert("message".to_string(), self.message(text, &options));
        if let Some(configuration) = options.configuration {
            params.insert("configuration".to_string(), configuration);
        }
        self.stream_events("SendStreamingMessage", Value::Object(params))
            .await
    }

    pub async fn get_task(
        &self,
        task_id: &str,
        options: A2ATaskOptions,
    ) -> Result<Value, A2AError> {
        self.rpc("GetTask", self.task_params(task_id, &options))
            .await
    }

    pub async fn cancel_task(
        &self,
        task_id: &str,
        options: A2ATaskOptions,
    ) -> Result<Value, A2AError> {
        self.rpc("CancelTask", self.task_params(task_id, &options))
            .await
    }

    pub async fn list_tasks(&self, options: A2AListTasksOptions) -> Result<Value, A2AError> {
        let mut params = Map::new();
        params.insert(
            "includeArtifacts".to_string(),
            Value::Bool(options.include_artifacts),
        );
        if let Some(context_id) = options.context_id {
            params.insert("contextId".to_string(), Value::String(context_id));
        }
        if let Some(status) = options.status {
            params.insert("status".to_string(), Value::String(status));
        }
        if let Some(page_size) = options.page_size {
            params.insert("pageSize".to_string(), Value::Number(page_size.into()));
        }
        if let Some(page_token) = options.page_token {
            params.insert("pageToken".to_string(), Value::String(page_token));
        }
        if let Some(history_length) = options.history_length {
            params.insert(
                "historyLength".to_string(),
                Value::Number(history_length.into()),
            );
        }
        self.rpc("ListTasks", Value::Object(params)).await
    }

    pub async fn set_task_push_notification_config(
        &self,
        task_id: &str,
        options: A2APushNotificationConfigOptions,
    ) -> Result<Value, A2AError> {
        let mut params = Map::new();
        params.insert("taskId".to_string(), Value::String(task_id.to_string()));
        params.insert(
            "id".to_string(),
            Value::String(options.config_id.unwrap_or_else(|| self.new_id("push"))),
        );
        params.insert("url".to_string(), Value::String(options.url));
        if let Some(token) = options.token {
            params.insert("token".to_string(), Value::String(token));
        }
        if let Some(authentication) = options.authentication {
            params.insert("authentication".to_string(), authentication);
        }
        self.rpc("CreateTaskPushNotificationConfig", Value::Object(params))
            .await
    }

    pub async fn get_task_push_notification_config(
        &self,
        task_id: &str,
        config_id: &str,
    ) -> Result<Value, A2AError> {
        self.rpc(
            "GetTaskPushNotificationConfig",
            json!({"taskId": task_id, "id": config_id}),
        )
        .await
    }

    pub async fn list_task_push_notification_configs(
        &self,
        task_id: &str,
    ) -> Result<Value, A2AError> {
        self.rpc(
            "ListTaskPushNotificationConfigs",
            json!({"taskId": task_id}),
        )
        .await
    }

    pub async fn delete_task_push_notification_config(
        &self,
        task_id: &str,
        config_id: &str,
    ) -> Result<Value, A2AError> {
        self.rpc(
            "DeleteTaskPushNotificationConfig",
            json!({"taskId": task_id, "id": config_id}),
        )
        .await
    }

    pub async fn subscribe_to_task(
        &self,
        task_id: &str,
        options: A2ATaskOptions,
    ) -> Result<Vec<Value>, A2AError> {
        self.stream("SubscribeToTask", self.task_params(task_id, &options))
            .await
    }

    pub async fn subscribe_to_task_events(
        &self,
        task_id: &str,
        options: A2ATaskOptions,
    ) -> Result<A2AEventStream, A2AError> {
        self.stream_events("SubscribeToTask", self.task_params(task_id, &options))
            .await
    }

    pub async fn rpc(&self, method: &str, params: Value) -> Result<Value, A2AError> {
        let payload = self
            .request_json(
                self.http
                    .post(format!("{}/rpc", self.base_url))
                    .json(&self.rpc_payload(method, params)),
            )
            .await?;
        extract_result(payload)
    }

    pub async fn stream(&self, method: &str, params: Value) -> Result<Vec<Value>, A2AError> {
        let mut results = Vec::new();
        self.stream_with_handler(method, params, |event| {
            results.push(event);
            Ok(())
        })
        .await?;
        Ok(results)
    }

    pub async fn stream_events(
        &self,
        method: &str,
        params: Value,
    ) -> Result<A2AEventStream, A2AError> {
        let response = self
            .request_stream(
                self.http
                    .post(format!("{}/rpc", self.base_url))
                    .header("Accept", "text/event-stream")
                    .json(&self.stream_payload(method, params)),
            )
            .await?;

        let state = (
            Box::pin(response.bytes_stream())
                as Pin<Box<dyn Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>>,
            String::new(),
            false,
        );

        let events = stream::unfold(state, |(mut body, mut buffer, mut finished)| async move {
            loop {
                match pop_sse_event(&mut buffer, finished) {
                    Ok(Some(event)) => return Some((Ok(event), (body, buffer, finished))),
                    Ok(None) if finished => return None,
                    Err(err) => return Some((Err(err), (body, buffer, true))),
                    Ok(None) => {}
                }

                match body.next().await {
                    Some(Ok(chunk)) => match std::str::from_utf8(&chunk) {
                        Ok(text) => buffer.push_str(text),
                        Err(err) => {
                            return Some((
                                Err(A2AError::UnexpectedPayload(err.to_string())),
                                (body, buffer, true),
                            ))
                        }
                    },
                    Some(Err(err)) => {
                        return Some((Err(A2AError::Network(err)), (body, buffer, true)))
                    }
                    None => finished = true,
                }
            }
        });

        Ok(Box::pin(events))
    }

    pub async fn stream_with_handler<F>(
        &self,
        method: &str,
        params: Value,
        mut on_event: F,
    ) -> Result<(), A2AError>
    where
        F: FnMut(Value) -> Result<(), A2AError>,
    {
        let response = self
            .request_stream(
                self.http
                    .post(format!("{}/rpc", self.base_url))
                    .header("Accept", "text/event-stream")
                    .json(&self.stream_payload(method, params)),
            )
            .await?;

        let mut body = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            let chunk = std::str::from_utf8(&chunk)
                .map_err(|err| A2AError::UnexpectedPayload(err.to_string()))?;
            buffer.push_str(chunk);
            while let Some(event) = pop_sse_event(&mut buffer, false)? {
                on_event(event)?;
            }
        }

        while let Some(event) = pop_sse_event(&mut buffer, true)? {
            on_event(event)?;
        }
        Ok(())
    }

    async fn request_json(&self, request: reqwest::RequestBuilder) -> Result<Value, A2AError> {
        let mut request = request.header("Content-Type", "application/json");
        if let Some(api_token) = &self.api_token {
            request = request.bearer_auth(api_token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let payload = match response.text().await {
                Ok(text) => text,
                Err(err) => err.to_string(),
            };
            return Err(A2AError::HttpStatus {
                status_code: status.as_u16(),
                payload,
            });
        }

        let payload = response.json::<Value>().await?;
        if !payload.is_object() {
            return Err(A2AError::UnexpectedPayload(payload.to_string()));
        }
        Ok(payload)
    }

    async fn request_stream(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, A2AError> {
        let mut request = request.header("Content-Type", "application/json");
        if let Some(api_token) = &self.api_token {
            request = request.bearer_auth(api_token);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let payload = match response.text().await {
                Ok(text) => text,
                Err(err) => err.to_string(),
            };
            return Err(A2AError::HttpStatus {
                status_code: status.as_u16(),
                payload,
            });
        }
        Ok(response)
    }

    fn message(&self, text: &str, options: &A2AMessageOptions) -> Value {
        let mut message = Map::new();
        message.insert(
            "messageId".to_string(),
            Value::String(
                options
                    .message_id
                    .clone()
                    .unwrap_or_else(|| self.new_id("msg")),
            ),
        );
        message.insert("role".to_string(), Value::String("user".to_string()));
        message.insert("parts".to_string(), json!([{ "text": text }]));
        if let Some(task_id) = &options.task_id {
            message.insert("taskId".to_string(), Value::String(task_id.clone()));
        }
        if let Some(context_id) = &options.context_id {
            message.insert("contextId".to_string(), Value::String(context_id.clone()));
        }
        if let Some(metadata) = &options.metadata {
            message.insert("metadata".to_string(), metadata.clone());
        }
        Value::Object(message)
    }

    fn task_params(&self, task_id: &str, options: &A2ATaskOptions) -> Value {
        let mut params = Map::new();
        params.insert("id".to_string(), Value::String(task_id.to_string()));
        params.insert(
            "includeArtifacts".to_string(),
            Value::Bool(options.include_artifacts),
        );
        if let Some(history_length) = options.history_length {
            params.insert(
                "historyLength".to_string(),
                Value::Number(history_length.into()),
            );
        }
        Value::Object(params)
    }

    fn new_id(&self, prefix: &str) -> String {
        format!("{}-{}", prefix, uuid_like())
    }

    fn rpc_payload(&self, method: &str, params: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.new_id("rpc"),
            "method": method,
            "params": match params {
                Value::Object(_) => params,
                _ => json!({}),
            },
        })
    }

    fn stream_payload(&self, method: &str, params: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.new_id("stream"),
            "method": method,
            "params": match params {
                Value::Object(_) => params,
                _ => json!({}),
            },
        })
    }
}

pub fn supported_interfaces(card: &Value) -> Vec<Map<String, Value>> {
    card.get("supportedInterfaces")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn extension_uris(card: &Value) -> Vec<String> {
    card.get("capabilities")
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get("extensions"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .filter_map(|item| item.get("uri").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn supports_extension(card: &Value, uri: &str) -> bool {
    extension_uris(card)
        .iter()
        .any(|candidate| candidate == uri)
}

pub fn supports_talos_secure_channels(card: &Value) -> bool {
    supports_extension(card, TALOS_SECURE_CHANNELS_EXTENSION)
}

pub fn supports_talos_attestation(card: &Value) -> bool {
    supports_extension(card, TALOS_ATTESTATION_EXTENSION)
}

pub fn supports_talos_compat_jsonrpc(card: &Value) -> bool {
    supports_extension(card, TALOS_COMPAT_JSONRPC_EXTENSION)
}

fn extract_result(payload: Value) -> Result<Value, A2AError> {
    if let Some(error) = payload.get("error").and_then(Value::as_object) {
        return Err(A2AError::JsonRpc {
            code: error.get("code").and_then(Value::as_i64).unwrap_or(-32603),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("JSON-RPC error")
                .to_string(),
            data: error.get("data").cloned(),
        });
    }

    let result = payload
        .get("result")
        .cloned()
        .ok_or_else(|| A2AError::UnexpectedPayload(payload.to_string()))?;
    if !result.is_object() {
        return Err(A2AError::UnexpectedPayload(result.to_string()));
    }
    Ok(result)
}

fn extract_stream_results(payload: &str) -> Result<Vec<Value>, A2AError> {
    let mut results = Vec::new();
    let mut buffer = payload.to_string();
    drain_sse_buffer(&mut buffer, true, &mut |event| {
        results.push(event);
        Ok(())
    })?;
    Ok(results)
}

fn pop_sse_event(buffer: &mut String, flush: bool) -> Result<Option<Value>, A2AError> {
    while let Some(newline) = buffer.find('\n') {
        let line = buffer[..newline].trim_end_matches('\r').trim().to_string();
        buffer.drain(..=newline);
        if let Some(event) = process_sse_line(&line)? {
            return Ok(Some(event));
        }
    }

    if flush && !buffer.trim().is_empty() {
        let line = buffer.trim().to_string();
        buffer.clear();
        if let Some(event) = process_sse_line(&line)? {
            return Ok(Some(event));
        }
    }

    Ok(None)
}

fn drain_sse_buffer<F>(buffer: &mut String, flush: bool, on_event: &mut F) -> Result<(), A2AError>
where
    F: FnMut(Value) -> Result<(), A2AError>,
{
    while let Some(event) = pop_sse_event(buffer, flush)? {
        on_event(event)?;
    }

    Ok(())
}

fn process_sse_line(line: &str) -> Result<Option<Value>, A2AError> {
    if !line.starts_with("data: ") {
        return Ok(None);
    }
    let raw_payload = line.trim_start_matches("data: ").trim();
    if raw_payload.is_empty() {
        return Ok(None);
    }
    let event: Value = serde_json::from_str(raw_payload)
        .map_err(|err| A2AError::UnexpectedPayload(err.to_string()))?;
    Ok(Some(extract_result(event)?))
}

fn uuid_like() -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        rand::random::<u32>(),
        rand::random::<u16>(),
        rand::random::<u16>(),
        rand::random::<u16>(),
        rand::random::<u64>() & 0x0000ffffffffffff,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn gets_agent_card_and_reports_extensions() {
        let card = json!({
            "supportedInterfaces": [{"transport":"https","url":"https://example.test/rpc"}],
            "capabilities": {
                "extensions": [
                    {"uri": TALOS_SECURE_CHANNELS_EXTENSION},
                    {"uri": TALOS_ATTESTATION_EXTENSION}
                ]
            }
        });

        assert_eq!(supported_interfaces(&card).len(), 1);
        assert!(supports_talos_secure_channels(&card));
        assert!(supports_talos_attestation(&card));
        assert!(!supports_talos_compat_jsonrpc(&card));
    }

    #[test]
    fn uses_canonical_json_rpc_methods() {
        let client = A2AJsonRpcClient::new("https://example.test").with_api_token("sk-test");
        let get_extended = client.rpc_payload("GetExtendedAgentCard", json!({}));
        let send_message = client.rpc_payload(
            "SendMessage",
            json!({
                "message": client.message("hello", &A2AMessageOptions::default()),
            }),
        );

        assert_eq!(get_extended["method"], "GetExtendedAgentCard");
        assert_eq!(send_message["method"], "SendMessage");
    }

    #[test]
    fn uses_canonical_streaming_methods() {
        let client = A2AJsonRpcClient::new("https://example.test").with_api_token("sk-test");
        let send_stream = client.stream_payload(
            "SendStreamingMessage",
            json!({
                "message": client.message("hello", &A2AMessageOptions::default()),
            }),
        );
        let subscribe = client.stream_payload(
            "SubscribeToTask",
            client.task_params("task-1", &A2ATaskOptions::default()),
        );

        assert_eq!(send_stream["method"], "SendStreamingMessage");
        assert_eq!(subscribe["method"], "SubscribeToTask");
    }

    #[test]
    fn surfaces_json_rpc_errors() {
        let error = extract_result(json!({
            "jsonrpc": "2.0",
            "id": "rpc-err",
            "error": {
                "code": -32603,
                "message": "rpc failed",
                "data": {"reason": "denied"}
            }
        }))
        .expect_err("json-rpc error");

        match error {
            A2AError::JsonRpc {
                code,
                message,
                data,
            } => {
                assert_eq!(code, -32603);
                assert_eq!(message, "rpc failed");
                assert_eq!(data.expect("error data")["reason"], "denied");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn extracts_stream_results_and_errors() {
        let events = extract_stream_results(
            "event: message\n\
             data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-1\",\"result\":{\"index\":1}}\n\n\
             data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-2\",\"result\":{\"index\":2}}\n",
        )
        .expect("stream results");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["index"], 1);
        assert_eq!(events[1]["index"], 2);

        let error = extract_stream_results(
            "data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-err\",\"error\":{\"code\":-32000,\"message\":\"stream failed\",\"data\":{\"reason\":\"denied\"}}}\n",
        )
        .expect_err("stream error");

        match error {
            A2AError::JsonRpc { code, message, .. } => {
                assert_eq!(code, -32000);
                assert_eq!(message, "stream failed");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn drains_partial_sse_buffers_incrementally() {
        let mut buffer =
            String::from("data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-1\",\"result\":{\"index\":1}}\n");
        let mut seen = Vec::new();

        drain_sse_buffer(&mut buffer, false, &mut |event| {
            seen.push(event["index"].as_i64().expect("stream index"));
            Ok(())
        })
        .expect("first chunk should parse");

        assert_eq!(seen, vec![1]);
        assert!(buffer.is_empty());

        buffer.push_str("data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-2\",\"result\":{\"index\":2}}");
        drain_sse_buffer(&mut buffer, true, &mut |event| {
            seen.push(event["index"].as_i64().expect("stream index"));
            Ok(())
        })
        .expect("final chunk should parse");

        assert_eq!(seen, vec![1, 2]);
    }

    #[tokio::test]
    async fn streams_events_as_async_stream() {
        let base_url = spawn_test_server(
            "data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-1\",\"result\":{\"index\":1}}\n\n\
             data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-2\",\"result\":{\"index\":2}}\n\n",
        )
        .await;

        let client = A2AJsonRpcClient::new(base_url);
        let mut events = client
            .send_streaming_message_events("hello", A2AMessageOptions::default())
            .await
            .expect("event stream");

        assert_eq!(
            events
                .next()
                .await
                .expect("first event")
                .expect("first result")["index"],
            1
        );
        assert_eq!(
            events
                .next()
                .await
                .expect("second event")
                .expect("second result")["index"],
            2
        );
        assert!(events.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_events_surface_json_rpc_errors() {
        let base_url = spawn_test_server(
            "data: {\"jsonrpc\":\"2.0\",\"id\":\"evt-err\",\"error\":{\"code\":-32000,\"message\":\"stream failed\",\"data\":{\"reason\":\"denied\"}}}\n\n",
        )
        .await;

        let client = A2AJsonRpcClient::new(base_url);
        let mut events = client
            .subscribe_to_task_events("task-1", A2ATaskOptions::default())
            .await
            .expect("event stream");

        let error = events
            .next()
            .await
            .expect("error item")
            .expect_err("json-rpc stream error");
        match error {
            A2AError::JsonRpc { code, message, .. } => {
                assert_eq!(code, -32000);
                assert_eq!(message, "stream failed");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    async fn spawn_test_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let address = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.expect("read request");

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });

        format!("http://{}", address)
    }
}
