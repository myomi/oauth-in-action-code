import * as express from "express";
import * as consolidate from "consolidate";
import { AddressInfo } from "net";
import * as request from "request";
import * as url from "url";
import * as querystring from "querystring";
import * as randomstring from "randomstring";

const app = express();

app.engine("html", consolidate.underscore);
app.set("view engine", "html");
app.set("views", "files/client");
app.use("/", express.static("files/client"));

// authorization server information
const authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize", // 認可コードの要求
  tokenEndpoint: "http://localhost:9001/token" // アクセストークンの要求
};

// client information
const client = {
  client_id: "oauth-client-1",
  client_secret: "oauth-client-secret-1",
  redirect_uris: ["http://localhost:9000/callback"]
};

const protectedResource = "http://localhost:9002/resource";

interface Session {
  state: string;
  access_token: string;
  scope: string;
}

interface AuthorizeRequest {
  response_type: ResponseType;
  client_id: string;
  redirect_uri: string;
  state: string;
}

enum ResponseType {
  code = "code" // コード認可
}

enum GrantType {
  authorizationCode = "authorization_code" // 認可コード
}

let session: Session = {
  state: null,
  access_token: null,
  scope: null
};

/**
 * ホームページ
 */
app.get("/", (req, res) => {
  res.render("index", session);
});

/**
 * 認可の要求を行う。
 * 認可サーバのページにリダイレクトする
 */
app.get("/authorize", (req, res) => {
  session = {
    state: randomstring.generate(),
    access_token: null,
    scope: null
  };
  const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: ResponseType.code,
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: session.state
  });
  console.log("redirect to", authorizeUrl);
  res.redirect(authorizeUrl);
});

/**
 * 認可サーバでの処理終了後に呼び出されるコールバック。
 * アクセストークンの取得を行う
 */
app.get("/callback", async (req, res) => {
  if (req.query.error) {
    // 認可サーバからエラーが返ってきた場合
    res.render("error", { error: req.query.error });
    return;
  }
  if (req.query.state !== session.state) {
    // リクエスト時とは異なるstateで返ってきた。
    console.log(
      `State DOES NOT MATCH: expected ${session.state} got ${req.query.state}`
    );
    res.render("error", { error: "State value did not match" });
    return;
  }

  try {
    const response = await post(authServer.tokenEndpoint, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${encodeClientCredentials(
          client.client_id,
          client.client_secret
        )}`,
        Accepted: "application/json"
      },
      form: {
        grant_type: GrantType.authorizationCode,
        code: req.query.code,
        redirect_uri: client.redirect_uris[0]
      }
    });
    if (response.statusCode >= 200 && response.statusCode < 300) {
      // アクセストークンを取得
      session.access_token = JSON.parse(response.body).access_token;
      res.render("index", session);
    } else {
      // アクセストークン取得に失敗
      res.render(
        "error",
        `Unable to fetch access token, serverresponse: ${response.statusCode}`
      );
    }
  } catch (error) {
    res.render("error", { error });
  }
});

/**
 * リソースサーバにアクセスし、情報を取得する。
 * 事前にアクセストークンを取得しておく必要あり。
 */
app.get("/fetch_resource", async (req, res) => {
  if (!session.access_token) {
    // アクセストークンなし
    res.render("error", { error: "Missing Access Token" });
  }
  try {
    const response = await post(protectedResource, {
      headers: {
        Authorization: `Bearer ${session.access_token}`
      }
    });
    if (response.statusCode >= 200 && response.statusCode < 300) {
      // リソースを取得
      res.render("data", { resource: JSON.parse(response.body) });
    } else {
      // リソース取得に失敗
      session.access_token = null;
      res.render(
        "error",
        `Unable to fetch resource, serverresponse: ${response.statusCode}`
      );
    }
  } catch (error) {
    res.render("error", { error });
  }
});



const server = app.listen(9000, "localhost", () => {
  const address = server.address() as AddressInfo;
  console.log(
    `OAuth Client is listening at http://${address.address}:${address.port}`
  );
});

/**
 * 認可サーバへの問い合わせ用URLを構築する
 * @param base URL
 * @param options クエリパラメータ
 * @param hash URLハッシュ
 */
function buildUrl(base: string, options: AuthorizeRequest, hash?: string) {
  const newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  Object.keys(options).forEach(key => {
    newUrl.query[key] = options[key];
  });
  if (hash) {
    newUrl.hash = hash;
  }
  return url.format(newUrl);
}

/**
 * clientIDとシークレットで、Basic認証用のクレデンシャルを作成する
 * @param clientId クライアントID
 * @param clientSecret シークレット
 */
function encodeClientCredentials(
  clientId: string,
  clientSecret: string
): string {
  return Buffer.from(
    querystring.escape(clientId) + ":" + querystring.escape(clientSecret)
  ).toString("base64");
}

/**
 * request.post() の Promiseラッパー
 * @param url APIのURL
 * @param options APIに渡すオプション
 */
function post(
  url: string,
  options: request.CoreOptions
): Promise<request.Response> {
  const result = new Promise<request.Response>((resolve, reject) => {
    request.post(url, options, (error, response) => {
      if (error) {
        reject(error);
      } else {
        resolve(response);
      }
    });
  });
  return result;
}
