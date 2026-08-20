"""Statically typed facade for BriXTest's lazy public author API."""

from brixtest.auth import (
    AuthRecipe as AuthRecipe,
    KerberosAuth as KerberosAuth,
    MaterializedAuth as MaterializedAuth,
    TLSAuth as TLSAuth,
    TokenAuth as TokenAuth,
    VOMSAuth as VOMSAuth,
    decode_token as decode_token,
    issue_token as issue_token,
    kerberos_auth as kerberos_auth,
    tls_auth as tls_auth,
    token_auth as token_auth,
    verify_token as verify_token,
    voms_auth as voms_auth,
)
from brixtest.clients.configured import (
    ConfiguredClient as ConfiguredClient,
    ConfiguredTool as ConfiguredTool,
)
from brixtest.credentials import (
    Credential as Credential,
    MaterializedCredential as MaterializedCredential,
    checksum_credential as checksum_credential,
    credential as credential,
    signed_credential as signed_credential,
)
from brixtest.design import (
    Artifact as Artifact,
    Binary as Binary,
    CaseDefinition as CaseDefinition,
    Client as Client,
    ConfigFile as ConfigFile,
    ConfigSet as ConfigSet,
    ConfigTemplate as ConfigTemplate,
    GB as GB,
    GiB as GiB,
    KB as KB,
    KiB as KiB,
    MB as MB,
    MiB as MiB,
    Readiness as Readiness,
    Server as Server,
    Tool as Tool,
    artifact as artifact,
    binary as binary,
    case as case,
    client as client,
    configs as configs,
    file_artifact as file_artifact,
    get_case as get_case,
    immediate as immediate,
    is_case as is_case,
    load_template as load_template,
    noise as noise,
    server as server,
    server_config as server_config,
    static_config as static_config,
    tcp as tcp,
    template_config as template_config,
    text_artifact as text_artifact,
    tool as tool,
)
from brixtest.errors import (
    BriXTestError as BriXTestError,
    CaseRunError as CaseRunError,
    HelperProcessError as HelperProcessError,
    SpecError as SpecError,
    TemplateError as TemplateError,
)
from brixtest.evidence import (
    CollectorSpec as CollectorSpec,
    collector as collector,
    kubernetes_events as kubernetes_events,
    process_tree as process_tree,
    prometheus as prometheus,
    structured_logs as structured_logs,
)
from brixtest.extensions import (
    ExtensionInfo as ExtensionInfo,
    ExtensionRegistry as ExtensionRegistry,
    get_extension as get_extension,
    installed_extensions as installed_extensions,
    register_extension as register_extension,
)
from brixtest.introspection import api_contract as api_contract
from brixtest.isolation import (
    Isolation as Isolation,
    docker as docker,
    nsenter as nsenter,
    podman as podman,
    process as process,
    runc as runc,
)
from brixtest.metrics import (
    MetricRecorder as MetricRecorder,
    MetricSample as MetricSample,
    MetricTimer as MetricTimer,
)
from brixtest.network import HostMapping as HostMapping, host_mapping as host_mapping
from brixtest.resources import (
    Command as Command,
    Endpoint as Endpoint,
    Execution as Execution,
    Lifecycle as Lifecycle,
    LogPolicy as LogPolicy,
    Mount as Mount,
    Placement as Placement,
    Probe as Probe,
    Reference as Reference,
    ResourceLimits as ResourceLimits,
    artifact_ref as artifact_ref,
    binary_ref as binary_ref,
    command as command,
    config_ref as config_ref,
    credential_ref as credential_ref,
    endpoint as endpoint,
    exec_probe as exec_probe,
    execution as execution,
    http_endpoint as http_endpoint,
    http_probe as http_probe,
    mount as mount,
    param as param,
    probe as probe,
    ref as ref,
    run_root_ref as run_root_ref,
    server_ref as server_ref,
    workspace_ref as workspace_ref,
)
from brixtest.runtime.api import Run as Run, Service as Service
from brixtest.runtime.artifacts import (
    ArtifactProviderContext as ArtifactProviderContext,
    MaterializedArtifact as MaterializedArtifact,
)
from brixtest.runtime.backends import BackendContext as BackendContext
from brixtest.runtime.binaries import CapturedBinary as CapturedBinary
from brixtest.runtime.commands import CommandResult as CommandResult
from brixtest.runtime.executors import (
    ToolExecutionContext as ToolExecutionContext,
    ToolExecutionRequest as ToolExecutionRequest,
)
from brixtest.runtime.launchers import (
    ServerLaunchContext as ServerLaunchContext,
    ServerLaunchPlan as ServerLaunchPlan,
    ServerLaunchRequest as ServerLaunchRequest,
)
from brixtest.runtime.manager import CaseManager as CaseManager

__version__: str
__all__: list[str]

def __dir__() -> list[str]: ...
