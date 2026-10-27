//! Versioned HTTP projections of the same authorized model catalog.
//!
//! v1 is the published 0.2.10 response shape, not a second model registry.
//! Never change execution facts or infer a client version from its identity.

use astra_core::{ErrorResponse, error_response_coded};
use astra_server_types::{MODEL_CATALOG_VERSION, MODEL_CATALOG_VERSION_HEADER};
use astra_services::models::{
    ModelAccessAction, ModelAccessKind, ModelAccessProjectionResponse, ModelAccessReason,
    ModelAccessStatus, ModelAccessViewResponse, ModelDefaultInvalidReason, ModelDefaultResolution,
    ModelDefaultScope, ModelDefaultSource, ModelExecutionPlacement, ModelListCursor,
    ModelListItemResponse, ModelListPageResponse, ThinkingCapability,
};
use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Clone, Copy)]
pub(super) enum CatalogVersion {
    Legacy,
    Current,
}

impl CatalogVersion {
    pub(super) fn from_headers(
        headers: &HeaderMap,
    ) -> Result<Self, (StatusCode, Json<ErrorResponse>)> {
        let mut values = headers.get_all(MODEL_CATALOG_VERSION_HEADER).iter();
        let first = values.next();
        if values.next().is_none() {
            match first.map(HeaderValue::as_bytes) {
                None | Some(b"1") => return Ok(Self::Legacy),
                Some(value) if value == MODEL_CATALOG_VERSION.as_bytes() => {
                    return Ok(Self::Current);
                }
                _ => {}
            }
        }
        Err(error_response_coded(
            StatusCode::BAD_REQUEST,
            "Unsupported model catalog response version. This server supports versions 1 and 2; update Astra to use its supported catalog format.",
            "model_catalog_version_unsupported",
        ))
    }

    fn response(self, value: impl Serialize) -> Response {
        let mut response = Json(value).into_response();
        let headers = response.headers_mut();
        headers.insert(
            MODEL_CATALOG_VERSION_HEADER,
            HeaderValue::from_static(match self {
                Self::Legacy => "1",
                Self::Current => MODEL_CATALOG_VERSION,
            }),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.append(
            header::VARY,
            HeaderValue::from_static(MODEL_CATALOG_VERSION_HEADER),
        );
        response
    }

    pub(super) fn models(self, page: ModelListPageResponse) -> Response {
        match self {
            Self::Current => self.response(page),
            Self::Legacy => self.response(LegacyModelPage {
                items: page.items.into_iter().map(LegacyModel::from).collect(),
                next_cursor: page.next_cursor.map(LegacyCursor::from),
                limit: page.limit,
                total: page.total,
                catalog_revision: page.catalog_revision,
            }),
        }
    }

    pub(super) fn access(self, page: ModelAccessProjectionResponse) -> Response {
        match self {
            Self::Current => self.response(page),
            Self::Legacy => self.response(LegacyModelAccess {
                accesses: page
                    .accesses
                    .into_iter()
                    .map(LegacyAccessView::from)
                    .collect(),
                offerings: page.offerings.into_iter().map(LegacyModel::from).collect(),
                default_offering_id: page.default_offering_id,
                default_resolution: page.default_resolution.map(LegacyDefaultResolution::from),
                next_cursor: page.next_cursor.map(LegacyCursor::from),
                limit: page.limit,
                total: page.total,
                catalog_revision: page.catalog_revision,
                observed_at: page.observed_at,
            }),
        }
    }
}

// Frozen field set from astra-services at 5aacae0d399906958f0c93f605a8c68641ab9a7b.
// Additions belong in an explicitly negotiated format, never in this struct.
#[derive(Serialize)]
struct LegacyModel {
    offering_id: String,
    access_id: String,
    access_kind: ModelAccessKind,
    access_label: String,
    execution_placement: ModelExecutionPlacement,
    name: String,
    provider: String,
    description: Option<String>,
    is_active: bool,
    context_window: i32,
    max_completion_tokens: Option<i32>,
    architecture: Option<String>,
    thinking_capability: Option<ThinkingCapability>,
}

impl From<ModelListItemResponse> for LegacyModel {
    fn from(item: ModelListItemResponse) -> Self {
        Self {
            offering_id: item.offering_id,
            access_id: item.access_id,
            access_kind: item.access_kind,
            access_label: item.access_label,
            execution_placement: item.execution_placement,
            name: item.name,
            provider: item.provider,
            description: item.description,
            is_active: item.is_active,
            context_window: item.context_window,
            max_completion_tokens: item.max_completion_tokens,
            architecture: item.architecture,
            thinking_capability: item.thinking_capability,
        }
    }
}

#[derive(Serialize)]
struct LegacyModelPage {
    items: Vec<LegacyModel>,
    next_cursor: Option<LegacyCursor>,
    limit: u32,
    total: u32,
    catalog_revision: String,
}

#[derive(Serialize)]
struct LegacyModelAccess {
    accesses: Vec<LegacyAccessView>,
    offerings: Vec<LegacyModel>,
    default_offering_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_resolution: Option<LegacyDefaultResolution>,
    next_cursor: Option<LegacyCursor>,
    limit: u32,
    total: u32,
    catalog_revision: String,
    observed_at: String,
}

#[derive(Serialize)]
struct LegacyCursor {
    provider: String,
    model_name: String,
    model_id: String,
}

impl From<ModelListCursor> for LegacyCursor {
    fn from(cursor: ModelListCursor) -> Self {
        Self {
            provider: cursor.provider,
            model_name: cursor.model_name,
            model_id: cursor.model_id,
        }
    }
}

#[derive(Serialize)]
struct LegacyAccessView {
    id: String,
    kind: ModelAccessKind,
    label: String,
    execution_placement: ModelExecutionPlacement,
    status: ModelAccessStatus,
    reason: Option<ModelAccessReason>,
    usable: bool,
    retry_after_seconds: Option<u32>,
    available_model_count: u32,
    actions: Vec<ModelAccessAction>,
}

impl From<ModelAccessViewResponse> for LegacyAccessView {
    fn from(view: ModelAccessViewResponse) -> Self {
        Self {
            id: view.id,
            kind: view.kind,
            label: view.label,
            execution_placement: view.execution_placement,
            status: view.status,
            reason: view.reason,
            usable: view.usable,
            retry_after_seconds: view.retry_after_seconds,
            available_model_count: view.available_model_count,
            actions: view.actions,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LegacyDefaultResolution {
    Selected {
        offering_id: String,
        source: ModelDefaultSource,
        scope: ModelDefaultScope,
    },
    Missing,
    Invalid {
        reason: ModelDefaultInvalidReason,
    },
}

impl From<ModelDefaultResolution> for LegacyDefaultResolution {
    fn from(resolution: ModelDefaultResolution) -> Self {
        match resolution {
            ModelDefaultResolution::Selected {
                offering_id,
                source,
                scope,
            } => Self::Selected {
                offering_id,
                source,
                scope,
            },
            ModelDefaultResolution::Missing => Self::Missing,
            ModelDefaultResolution::Invalid { reason } => Self::Invalid { reason },
        }
    }
}
