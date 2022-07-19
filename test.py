import asyncio
import time
from contextlib import asynccontextmanager

@asynccontextmanager
async def timeit():
    now = time.monotonic()
    try:
        yield now
    finally:
        print(f'it took {time.monotonic() - now}s to run')

@timeit()
async def main():
    print('test')

if __name__ == '__main__':
    asyncio.run(main())
