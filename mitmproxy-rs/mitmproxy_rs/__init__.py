import sys
import types

from .mitmproxy_rs import *

__doc__ = mitmproxy_rs.__doc__
if hasattr(mitmproxy_rs, "__all__"):
    __all__ = mitmproxy_rs.__all__

# Hacky workaround for https://github.com/PyO3/pyo3/issues/759
for k, v in vars(mitmproxy_rs).items():
    if isinstance(v, types.ModuleType):
        sys.modules[f"mitmproxy_rs.{k}"] = v
