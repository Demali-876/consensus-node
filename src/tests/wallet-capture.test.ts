import assert from "node:assert/strict";
import {
  isValidEvmAddress,
  isValidIcpAddress,
  isValidSolanaAddress,
  mergeWalletAddresses,
  normalizeWalletAddresses,
  startWalletAddressServer,
  validateWalletAddresses,
} from "../registration/wallet-capture";

assert.equal(isValidEvmAddress("0x0000000000000000000000000000000000000000"), true);
assert.equal(isValidEvmAddress("0x000000000000000000000000000000000000000"), false);
assert.equal(isValidSolanaAddress("11111111111111111111111111111111"), true);
assert.equal(isValidSolanaAddress("0OIl11111111111111111111111111111111"), false);
assert.equal(isValidIcpAddress("aaaaa-aa"), true);
assert.equal(isValidIcpAddress("AAAAA-AA"), false);

assert.deepEqual(normalizeWalletAddresses({
  evmAddress: "  0x0000000000000000000000000000000000000000  ",
  solanaAddress: "",
  icpAddress: "aaaaa-aa",
}), {
  evmAddress: "0x0000000000000000000000000000000000000000",
  solanaAddress: undefined,
  icpAddress: "aaaaa-aa",
});

assert.deepEqual(mergeWalletAddresses({
  evmAddress: "0x0000000000000000000000000000000000000000",
  solanaAddress: "11111111111111111111111111111111",
}, {
  icpAddress: "aaaaa-aa",
}), {
  evmAddress: "0x0000000000000000000000000000000000000000",
  solanaAddress: "11111111111111111111111111111111",
  icpAddress: "aaaaa-aa",
});

assert.deepEqual(validateWalletAddresses({
  evmAddress: "bad",
  solanaAddress: "11111111111111111111111111111111",
  icpAddress: "bad principal",
}), {
  evmAddress: "EVM address must be 0x followed by 40 hex characters",
  icpAddress: "ICP address must be a textual principal",
});

const session = await startWalletAddressServer({
  initialAddresses: {
    evmAddress: "0x0000000000000000000000000000000000000000",
  },
});

try {
  const page = await fetch(session.url);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.equal(html.includes("Connect your payout wallets"), true);
  assert.equal(html.includes("Connect MetaMask"), true);
  assert.equal(html.includes("Connect Phantom"), true);
  assert.equal(html.includes("Connect Plug"), true);
  assert.equal(html.includes("consensus-logo-light.svg"), true);
  assert.equal(html.includes("phantom.svg"), true);
  assert.equal(html.includes("plug.jpeg"), true);
  assert.equal(html.includes("0x0000000000000000000000000000000000000000"), true);

  const invalid = await fetch(session.url.replace(/token=[^&]+/, "token=wrong"));
  assert.equal(invalid.status, 403);

  const token = new URL(session.url).searchParams.get("token")!;
  const phantomAsset = await fetch(new URL(`/assets/phantom.svg?token=${token}`, session.url));
  assert.equal(phantomAsset.status, 200);
  assert.equal(phantomAsset.headers.get("content-type")?.includes("image/svg+xml"), true);
  const plugAsset = await fetch(new URL(`/assets/plug.jpeg?token=${token}`, session.url));
  assert.equal(plugAsset.status, 200);
  assert.equal(plugAsset.headers.get("content-type"), "image/jpeg");

  const submitUrl = new URL("/capture", session.url);
  submitUrl.searchParams.set("token", token);
  const submitted = await fetch(submitUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      evmAddress: "0x0000000000000000000000000000000000000000",
      solanaAddress: "11111111111111111111111111111111",
      icpAddress: "aaaaa-aa",
    }),
  });
  assert.equal(submitted.status, 200);

  const addresses = await session.done;
  assert.deepEqual(addresses, {
    evmAddress: "0x0000000000000000000000000000000000000000",
    solanaAddress: "11111111111111111111111111111111",
    icpAddress: "aaaaa-aa",
  });
} finally {
  await session.stop().catch(() => {});
}

console.log("wallet capture ok");
