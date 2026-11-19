import type { RecordAuthResponse } from "pocketbase";

import { COLLECTION_NAME_ADMIN, getPocketBase } from "./_pocketbase";

const pb = getPocketBase();
const pbco = pb.collection(COLLECTION_NAME_ADMIN);

const endpoint = "/api/dns-identity/admin";

export interface AdminCaptcha {
  required: boolean;
  id?: string;
  image?: string;
}

export interface AdminSecurityStatus {
  active: boolean;
  available: boolean;
  captcha: boolean;
}

interface CaptchaProof {
  captchaId?: string;
  captcha?: string;
}

interface AdminProof {
  password: string;
  code?: string;
}

export const getAdminCaptcha = () => pb.send<AdminCaptcha>(endpoint + "/captcha", { requestKey: null });
export const getAdminSecurity = () => pb.send<AdminSecurityStatus>(endpoint + "/security", { requestKey: null });

export const authWithPassword = (username: string, password: string, captcha: CaptchaProof) => {
  return pbco.authWithPassword(username, password, { body: { identity: username, password, ...captcha } });
};

export const requestAdminEmailCode = (email: string) => pbco.requestOTP(email);

export const authWithAdminEmailCode = (otpId: string, password: string, mfaId: string, captcha: CaptchaProof) => {
  return pbco.authWithOTP(otpId, password, { body: { otpId, password, ...captcha }, query: { mfaId } });
};

export const authWithAuthenticator = async (totpId: string, code: string) => {
  const result = await pb.send<RecordAuthResponse>(endpoint + "/totp/login", { method: "POST", body: { totpId, code } });
  pb.authStore.save(result.token, result.record);
};

export const setAdminCaptcha = (captcha: boolean, proof: AdminProof) => pb.send<void>(endpoint + "/policy", { method: "PUT", body: { ...proof, captcha } });

export const changeAdminPassword = (proof: AdminProof, newPassword: string, passwordConfirm: string) =>
  pb.send<void>(endpoint + "/password", { method: "POST", body: { ...proof, newPassword, passwordConfirm } });

export const generateAdminAuthenticator = (proof: AdminProof) => pb.send<{ uri: string }>(endpoint + "/totp/generate", { method: "POST", body: proof });
export const bindAdminAuthenticator = (proof: AdminProof) => pb.send<void>(endpoint + "/totp/bind", { method: "POST", body: proof });
export const removeAdminAuthenticator = (proof: AdminProof) => pb.send<void>(endpoint + "/totp/remove", { method: "POST", body: proof });

export const getAuthStore = () => {
  return pb.authStore;
};

export const save = (data: { email: string }) => {
  return pbco.update(getAuthStore().record?.id || "", data);
};
