import type { DataClass, Finding, TriageSummary } from "../schemas/index.js";

export type RiskDriver = TriageSummary["active_by_risk_driver"][number]["driver"];

export const riskDriverOrder = [
  "untrusted_to_privileged",
  "secret_exposure",
  "external_reach",
  "irreversible_action",
  "side_effect",
  "sensitive_data",
  "credential_data",
  "pii_data",
  "execute_action",
  "write_action"
] as const satisfies readonly RiskDriver[];

const sensitiveDataClasses = ["credential", "secret", "pii", "confidential"] as const satisfies readonly DataClass[];

export function riskDriversForFinding(finding: Finding): RiskDriver[] {
  const drivers = new Set<RiskDriver>();
  const dataClasses = new Set([...finding.data_classes, ...finding.risk.data_classes, ...finding.matched_object.data_classes]);
  const actions = new Set([...finding.risk.actions, ...finding.matched_object.actions]);
  const sideEffect = finding.risk.side_effect || finding.matched_object.side_effect;
  const reversible = finding.risk.reversible && finding.matched_object.reversible;
  const externalReach = finding.risk.external_reach || finding.matched_object.external_reach;
  const secretExposure = finding.risk.secret_exposure || finding.matched_object.secret_exposure;
  const untrustedToPrivileged = finding.risk.untrusted_to_privileged || finding.matched_object.untrusted_to_privileged;

  if (untrustedToPrivileged || finding.trust_boundary_crossed) drivers.add("untrusted_to_privileged");
  if (secretExposure) drivers.add("secret_exposure");
  if (externalReach) drivers.add("external_reach");
  if (!reversible) drivers.add("irreversible_action");
  if (sideEffect) drivers.add("side_effect");
  if (sensitiveDataClasses.some((dataClass) => dataClasses.has(dataClass))) drivers.add("sensitive_data");
  if (dataClasses.has("credential") || dataClasses.has("secret")) drivers.add("credential_data");
  if (dataClasses.has("pii")) drivers.add("pii_data");
  if (actions.has("execute") || actions.has("delete") || actions.has("approve")) drivers.add("execute_action");
  if (actions.has("write") || actions.has("publish") || actions.has("send") || actions.has("remember")) {
    drivers.add("write_action");
  }

  return riskDriverOrder.filter((driver) => drivers.has(driver));
}
