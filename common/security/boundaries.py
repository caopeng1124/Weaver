"""Decorators for research paths that do not go through an agent tool node."""

import copy
import inspect
from dataclasses import fields, is_dataclass
from functools import wraps

from common.security.content import enabled
from common.security.runtime import check_outbound, untrusted


def protect_result(result, source):
    if not enabled():
        return result
    if isinstance(result, list):
        return [protect_result(item, source) for item in result]
    if isinstance(result, tuple):
        return tuple(protect_result(item, source) for item in result)
    if is_dataclass(result) and not isinstance(result, type):
        result = copy.copy(result)
        data = {f.name: getattr(result, f.name) for f in fields(result)}
        safe = untrusted(data, source=str(data.get("url") or source))
        for key, value in safe.items():
            setattr(result, key, value)
        return result
    if isinstance(result, dict):
        return untrusted(result, source=str(result.get("url") or source))
    return untrusted(result, source=source)


def research_boundary(kind="search"):
    def decorate(function):
        signature = inspect.signature(function)

        def check(args, kwargs):
            bound = signature.bind(*args, **kwargs).arguments
            values = {k: bound[k] for k in ("query", "url", "urls") if k in bound}
            name = (
                "crawl_urls"
                if "urls" in values
                else "crawl_url"
                if "url" in values
                else "tavily_search"
            )
            check_outbound(name, values)
            return str(values.get("url") or function.__name__)

        if inspect.iscoroutinefunction(function):

            @wraps(function)
            async def async_wrapper(*args, **kwargs):
                source = check(args, kwargs)
                return protect_result(await function(*args, **kwargs), source)

            return async_wrapper

        @wraps(function)
        def wrapper(*args, **kwargs):
            source = check(args, kwargs)
            return protect_result(function(*args, **kwargs), source)

        return wrapper

    return decorate
