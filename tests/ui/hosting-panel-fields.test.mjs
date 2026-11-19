import assert from "node:assert/strict";
import { test } from "node:test";

import { panelAccessFields, panelDeploymentFields, panelFieldsSchema } from "../../ui/src/domain/hostingPanelFields.ts";

const schema = (fields) => panelFieldsSchema(fields, "Enter one credential.");
const panel = { serverUrl: "https://panel.example.test/", username: "fixture-user" };

test("Kangle accepts one authentication method and associates errors with both credential fields", () => {
  const kangle = schema(panelAccessFields.kangle);
  assert.equal(kangle.safeParse({ ...panel, password: "fixture-password" }).success, true);
  assert.equal(kangle.safeParse({ ...panel, securityKey: "fixture-key" }).success, true);
  for (const credentials of [{}, { password: "fixture-password", securityKey: "fixture-key" }]) {
    const result = kangle.safeParse({ ...panel, ...credentials });
    assert.equal(result.success, false);
    assert.deepEqual(result.error.issues.map((issue) => issue.path), [["password"], ["securityKey"]]);
  }
});

test("panel endpoints accept HTTPS and reject embedded credentials and query strings", () => {
  const lucky = schema(panelAccessFields.lucky);
  assert.equal(lucky.safeParse({ serverUrl: panel.serverUrl, apiToken: "fixture-token" }).success, true);
  for (const serverUrl of ["", "not a URL", "http://panel.example.test", "https://user@panel.example.test", "https://panel.example.test/?key=fixture"]) {
    assert.equal(lucky.safeParse({ serverUrl, apiToken: "fixture-token" }).success, false, serverUrl);
  }
});

test("deployment parameters preserve required identifiers, optional Kangle and Lucky targets and targetless console deployments", () => {
  for (const [provider, fields] of Object.entries(panelDeploymentFields)) {
    const s = schema(fields);
    const required = fields.filter((field) => !field.optional);
    assert.equal(s.safeParse({}).success, !required.length, provider);
    const sample = Object.fromEntries(required.map((field) => [field.name, "1"]));
    assert.equal(s.safeParse(sample).success, true, provider);
  }
  assert.equal(schema(panelDeploymentFields.kuocai).safeParse({ target: "site" }).success, false);
  assert.equal(schema(panelDeploymentFields.uusec).safeParse({ target: "-1", name: "sample" }).success, false);
});

test("fnOS port defaults to 22 and validates the OpenSSH SHA256 fingerprint", () => {
  assert.equal(panelAccessFields.fnos.find((field) => field.name === "port").initial, 22);
  const fnos = schema(panelAccessFields.fnos);
  const access = { host: "fnos.example.test", username: "fixture-user", password: "fixture-password", port: 22, hostKeyFingerprint: "SHA256:" + "A".repeat(43) };
  assert.equal(fnos.safeParse(access).success, true);
  assert.equal(fnos.safeParse({ ...access, port: 70000 }).success, false);
  assert.equal(fnos.safeParse({ ...access, hostKeyFingerprint: "unverified" }).success, false);
});
