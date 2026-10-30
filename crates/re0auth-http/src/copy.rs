//! User-facing copy for the server-rendered pages.
//!
//! One home for every Chinese string a person can see, so a wording change is a
//! single edit and a future locale switch replaces this module instead of the
//! markup. Protocol text is deliberately not here: `error_description`, problem
//! `detail`, audit targets and logs are diagnostic channels, and their stable
//! identifier is `code`, not prose.

pub(crate) const AUTH_ERROR_TITLE: &str = "登录未完成";

/// 内部错误只露这句，细节进日志
pub(crate) const SERVER_ERROR: &str = "服务暂时不可用，请稍后重试";

pub(crate) const LOGIN_REQUIRED: &str = "请先登录";
pub(crate) const BAD_REQUEST: &str = "请求参数不正确";
pub(crate) const PAGE_EXPIRED: &str = "页面已失效，请重试";
pub(crate) const LOGIN_EXPIRED: &str = "登录已失效，请重新登录";
pub(crate) const IDP_UNAVAILABLE: &str = "登录方式暂时不可用";
pub(crate) const IDP_UNKNOWN: &str = "未知的登录方式";
pub(crate) const IDP_REQUIRED: &str = "请选择登录方式";
pub(crate) const RATE_LIMITED: &str = "操作过于频繁，请稍后再试";
pub(crate) const NOT_FOUND: &str = "页面不存在";
pub(crate) const TICKET_INVALID: &str = "授权请求无效，请重新发起";

pub(crate) const MISSING_USER_CODE: &str = "缺少设备码";

pub(crate) const DEVICE_APPROVAL_TITLE: &str = "批准设备";
pub(crate) const DEVICE_CODE_LABEL: &str = "设备码";
pub(crate) const CLIENT_LABEL: &str = "客户端";
pub(crate) const SCOPES_LABEL: &str = "请求权限";
pub(crate) const DEVICE_APPROVAL_WARNING: &str =
    "只有在另一台设备上看到同一个设备码时才批准；否则请拒绝。";
pub(crate) const APPROVE_BUTTON: &str = "批准";
pub(crate) const DENY_BUTTON: &str = "拒绝";

pub(crate) const DEVICE_APPROVED_TITLE: &str = "设备已批准";
pub(crate) const DEVICE_APPROVED_MESSAGE: &str = "设备已获得授权，可以关闭此页面。";
pub(crate) const DEVICE_DENIED_TITLE: &str = "设备已拒绝";
pub(crate) const DEVICE_DENIED_MESSAGE: &str = "本次设备授权已被拒绝。";

pub(crate) const DEVICE_ERROR_TITLE: &str = "设备授权";
pub(crate) const DEVICE_ERROR_HEADING: &str = "无法处理设备授权";
