from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
import asyncio

async def test():
    try:
        print("Attempting to set onboarding_host in Options init...")
        opts = options.Options(onboarding_host="foo.com")
        print("Success in init")
    except Exception as e:
        print(f"Failed in init: {e}")

    print("Attempting to set post-creation...")
    opts = options.Options()
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    # Addons loaded now?
    if "onboarding_host" in master.options:
        print("onboarding_host exists after master init")
        master.options.onboarding_host = "foo.com"
        print(f"Set to: {master.options.onboarding_host}")
    else:
        print("onboarding_host STILL not in options")

if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    loop.run_until_complete(test())
