/**
 * /authorize のリクエストパラメータ
 */
export interface AuthorizeRequest {
  response_type: ResponseType;
  client_id: string;
  redirect_uri: string;
  state?: string;
  scope?: string;
}

export enum ResponseType {
  code = "code" // コード認可
}
