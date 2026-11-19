import { ClientResponseError } from "pocketbase";
import { getPocketBase } from "@/repository/_pocketbase";

export interface Zone {
  id: string;
  name: string;
  status: string;
}
export interface DNSRecord {
  id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  proxied: boolean;
  line?: string;
  priority?: number;
  description?: string;
  weight?: number;
  readOnly?: boolean;
}
export interface Page<T> {
  result: T[];
  result_info: { page: number; total_count: number };
}

export async function dnsRequest<T>(url: string, method = "GET", body?: object): Promise<T> {
  const result = await getPocketBase().send<BaseResponse<T>>(url, { method, body, requestKey: null });
  if (result.code !== 0) throw new ClientResponseError({ status: result.code, response: result });
  return result.data;
}
