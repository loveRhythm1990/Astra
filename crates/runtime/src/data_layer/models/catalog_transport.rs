//! Version negotiation for the existing authorized model catalog.
//!
//! Unversioned published 0.2.12 consumers require the complete v2 field set.
//! Never infer a client version from identity or strip execution metadata.

use astra_core::{ErrorResponse, error_response_coded};
use astra_server_types::{MODEL_CATALOG_VERSION, MODEL_CATALOG_VERSION_HEADER};
use astra_services::models::{ModelAccessProjectionResponse, ModelListPageResponse};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Clone, Copy)]
pub(super) struct CatalogVersion;

impl CatalogVersion {
    pub(super) fn from_headers(
        headers: &HeaderMap,
    ) -> Result<Self, (StatusCode, Json<ErrorResponse>)> {
        let mut values = headers.get_all(MODEL_CATALOG_VERSION_HEADER).iter();
        let first = values.next();
        if values.next().is_none() {
            match first.map(HeaderValue::as_bytes) {
                None => return Ok(Self),
                Some(value) if value == MODEL_CATALOG_VERSION.as_bytes() => return Ok(Self),
                _ => {}
            }
        }
        Err(error_response_coded(
            StatusCode::BAD_REQUEST,
            "Unsupported model catalog response version. This server supports version 2; update Astra to use its supported catalog format.",
            "model_catalog_version_unsupported",
        ))
    }

    fn response(self, value: impl Serialize) -> Response {
        let mut response = Json(value).into_response();
        let headers = response.headers_mut();
        headers.insert(
            MODEL_CATALOG_VERSION_HEADER,
            HeaderValue::from_static(MODEL_CATALOG_VERSION),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.append(
            header::VARY,
            HeaderValue::from_static(MODEL_CATALOG_VERSION_HEADER),
        );
        response
    }

    pub(super) fn models(self, page: ModelListPageResponse) -> Response {
        self.response(page)
    }

    pub(super) fn access(self, page: ModelAccessProjectionResponse) -> Response {
        self.response(page)
    }
}
