import functools
import sys
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Any, TypeVar, cast

T_co = TypeVar("T_co", covariant=True)
T_contra = TypeVar("T_contra", contravariant=True)


if sys.version_info >= (3, 10):
    from contextlib import aclosing
else:

    class aclosing(AbstractAsyncContextManager[T_co]):
        def __init__(self, thing: T_co):
            self.thing = thing

        async def __aenter__(self) -> T_co:
            return self.thing

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            tb: TracebackType | None,
        ) -> None:
            await self.thing.aclose()  # type: ignore


def asyncgeneratorcontextmanager(
    func: Callable[..., T_co]
) -> Callable[..., AbstractAsyncContextManager[T_co]]:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> AbstractAsyncContextManager[T_co]:
        return cast(AbstractAsyncContextManager[T_co], aclosing(func(*args, **kwargs)))

    return wrapper
