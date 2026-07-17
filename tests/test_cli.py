import asyncio
import sys

from aiohttp.test_utils import TestServer

from fuzzer.mock_server import build_app


async def _run_cli(*args: str) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "fuzzer.cli",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout.decode(), stderr.decode()


async def test_cli_exits_zero_on_a_clean_campaign():
    # a single turn against kv.set can't produce any findings: cross_turn_leak
    # needs at least one earlier marker to compare against, and both latency
    # detectors need more history than one turn — so this is a genuinely
    # clean run, not just a lucky one.
    server = TestServer(build_app())
    await server.start_server()
    try:
        url = str(server.make_url("/mcp"))
        returncode, stdout, stderr = await _run_cli(
            "--url", url, "--tool", "kv.set", "--arguments", '{"key": "a", "value": "b"}', "--turns", "1"
        )
    finally:
        await server.close()

    assert returncode == 0, stderr
    assert '"findings": []' in stdout


async def test_cli_exits_one_when_findings_are_raised():
    server = TestServer(build_app())
    await server.start_server()
    try:
        url = str(server.make_url("/mcp"))
        returncode, stdout, stderr = await _run_cli(
            "--url", url, "--tool", "kv.set", "--arguments", '{"key": "a", "value": "b"}', "--turns", "3"
        )
    finally:
        await server.close()

    assert returncode == 1, stderr
    assert "cross_turn_leak" in stdout


async def test_cli_reports_a_clean_error_for_malformed_arguments_json():
    returncode, stdout, stderr = await _run_cli(
        "--url", "http://127.0.0.1:1/mcp", "--tool", "noop", "--arguments", "{not valid json"
    )

    assert returncode == 2
    assert "not valid JSON" in stderr
    assert "Traceback" not in stderr


async def test_cli_reports_a_clean_error_for_malformed_header():
    returncode, stdout, stderr = await _run_cli(
        "--url", "http://127.0.0.1:1/mcp", "--tool", "noop", "--header", "NoEqualsSign"
    )

    assert returncode == 2
    assert "invalid --header" in stderr
    assert "Traceback" not in stderr


async def test_cli_completes_and_exits_nonzero_when_the_server_refuses_the_connection():
    # nothing is listening on this port — the campaign should still run to
    # completion and report the failure, not crash with a raw traceback.
    returncode, stdout, stderr = await _run_cli(
        "--url", "http://127.0.0.1:1/mcp", "--tool", "noop", "--arguments", "{}", "--turns", "3"
    )

    assert returncode == 1, stderr
    assert "Traceback" not in stderr
    assert '"campaign_error"' in stdout
