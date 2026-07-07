import test from "node:test";
import assert from "node:assert/strict";
import { evaluateSignPolicy } from "../src/background/policy";

const baseConfig = {
  enabled: true,
  challenge: "AbCdEfGhIjKlMnOp_1234",
  namespace: "myapp",
  origin: "http://localhost:8080",
  allowedOrigins: ["http://localhost:8080"],
  originScopes: { "http://localhost:8080": [{ namespace: "myapp" }] }
};

test("accepts localhost/127.0.0.1 origin equivalence", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    origin: "http://127.0.0.1:8080"
  });
  assert.equal(result.ok, true);
});

test("rejects origin mismatch", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    origin: "http://localhost:8081"
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.match(result.error, /Origin not allowed/);
  }
});

test("rejects namespace mismatch", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    namespace: "wrong-namespace"
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.match(result.error, /Extension Namespace/);
  }
});

test("rejects invalid challenge format", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    challenge: "bad!!"
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.error, "Invalid challenge format");
  }
});

test("rejects when origin has no namespace mapping", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    originScopes: {}
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.match(result.error, /No namespace configured for origin/);
  }
});

test("rejects company mismatch when company is configured for origin", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    company: "wrong-company",
    originScopes: {
      "http://localhost:8080": [{ company: "mycompany", namespace: "myapp" }]
    }
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.match(result.error, /Extension Company/);
  }
});

test("accepts one origin with multiple namespaces", () => {
  const result = evaluateSignPolicy({
    ...baseConfig,
    namespace: "registry-namespace-admin",
    originScopes: {
      "http://localhost:8080": [{ namespace: "registry-admin" }, { namespace: "registry-namespace-admin" }]
    }
  });
  assert.equal(result.ok, true);
});
