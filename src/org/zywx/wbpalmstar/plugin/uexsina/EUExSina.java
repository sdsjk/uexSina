package org.zywx.wbpalmstar.plugin.uexsina;

import java.io.InputStream;

import org.json.JSONException;
import org.json.JSONObject;
import org.zywx.wbpalmstar.base.BUtility;
import org.zywx.wbpalmstar.engine.EBrowserView;
import org.zywx.wbpalmstar.engine.universalex.EUExBase;
import org.zywx.wbpalmstar.engine.universalex.EUExCallback;
import org.zywx.wbpalmstar.engine.universalex.EUExUtil;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.os.Message;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.CookieManager;
import android.widget.Toast;

import com.sina.weibo.sdk.auth.Oauth2AccessToken;
import com.sina.weibo.sdk.auth.WeiboAuth;
import com.sina.weibo.sdk.auth.WeiboAuthListener;
import com.sina.weibo.sdk.auth.sso.SsoHandler;
import com.sina.weibo.sdk.exception.WeiboException;
import com.sina.weibo.sdk.net.RequestListener;
import com.sina.weibo.sdk.net.WeiboParameters;
import com.sina.weibo.sdk.openapi.StatusesAPI;
import com.sina.weibo.sdk.openapi.models.ErrorInfo;
import com.sina.weibo.sdk.openapi.models.Status;
import com.sina.weibo.sdk.utils.LogUtil;
import com.sina.weibo.sdk.utils.Utility;

public class EUExSina extends EUExBase {
	private static final String TAG = "EUExSina";
	private boolean isLogin = false;
	private Oauth2AccessToken mAccessToken;
	private StatusesAPI mStatusesAPI;

	/** 微博 Web 授权类，提供登陆等功能 */
	private static WeiboAuth mWeiboAuth;
	private static final String CALLBACK_GET_REGISTER_STATUS = "uexSina.registerCallBack";
	private static final String cbRegisterAppFunName = "uexSina.cbRegisterApp";
	private static final String CALLBACK_SHARE_STATUS = "uexSina.cbShare";
	private static final String CALLBACK_LOGIN_STATUS = "uexSina.cbLogin";
	private String token;
	private String openId;
    private static final String BUNDLE_DATA = "data";
    private static final int MSG_REGISTER_APP = 1;
    private static final int MSG_LOGIN = 2;

	public EUExSina(Context ctx, EBrowserView view) {
		super(ctx, view);
		EUExUtil.init(ctx);
		mAccessToken = AccessTokenKeeper.readAccessToken(mContext);
		mStatusesAPI = new StatusesAPI(mAccessToken);
	}

    public void registerApp(String[] params) {
        if (params == null || params.length < 1) {
            errorCallback(0, 0, "error params!");
            return;
        }
        Message msg = new Message();
        msg.obj = this;
        msg.what = MSG_REGISTER_APP;
        Bundle bd = new Bundle();
        bd.putStringArray(BUNDLE_DATA, params);
        msg.setData(bd);
        mHandler.sendMessage(msg);
    }

    private void registerAppMsg(String[] args) {
        if (mAccessToken != null && mAccessToken.isSessionValid()) {
            Log.i(TAG, "已经注册过，直接获取注册信息");
            jsCallback(CALLBACK_GET_REGISTER_STATUS, 0, EUExCallback.F_C_INT,
                    EUExCallback.F_C_SUCCESS);
            jsCallback(cbRegisterAppFunName, 0, EUExCallback.F_C_INT,
                    EUExCallback.F_C_SUCCESS);
            return;
        }

        if ((args == null) || (args.length < 2)) {
            return;
        }

        final String appKey = args[0];
        final String redirectUrl = args[2];

        auth(mContext, appKey, redirectUrl, Constants.SCOPE);
        mAccessToken = AccessTokenKeeper.readAccessToken(mContext);
        mStatusesAPI = new StatusesAPI(mAccessToken);
    }

    public void login(String[] params) {
        if (params == null || params.length < 1) {
            errorCallback(0, 0, "error params!");
            return;
        }
        Message msg = new Message();
        msg.obj = this;
        msg.what = MSG_LOGIN;
        Bundle bd = new Bundle();
        bd.putStringArray(BUNDLE_DATA, params);
        msg.setData(bd);
        mHandler.sendMessage(msg);
    }

    private void loginMsg(String[] params) {
        if ((params == null) || (params.length < 2)) {
            return;
        }
        final String appKey = params[0];
        final String redirectUrl = params[1];
        if(mAccessToken != null && mAccessToken.isSessionValid()) {
            jsCallback(CALLBACK_LOGIN_STATUS, 0, EUExCallback.F_C_INT, data2Json(mAccessToken));
        }else {
            isLogin = true;
            auth(mContext, appKey, redirectUrl, Constants.SCOPE);
        }
    }

	public void sendTextContent(String[] args) {
		if (args != null && args.length > 0) {
			if (mAccessToken != null && mAccessToken.isSessionValid()
					&& mStatusesAPI != null) {
				String text = args[0];
				mStatusesAPI.update(text, null, null, mListener);
			} else {
				Toast.makeText(
						mContext,
						EUExUtil.getResStringID("weibosdk_demo_toast_auth_register"),
						Toast.LENGTH_SHORT).show();
			}
		}
	}

	public void sendImageContent(String[] args) {
		if (mAccessToken == null || !mAccessToken.isSessionValid()
				&& mStatusesAPI != null) {
			Toast.makeText(
					mContext,
					EUExUtil.getResStringID("weibosdk_demo_toast_auth_register"),
					Toast.LENGTH_SHORT).show();
			return;
		}

		if (args != null && args.length > 1) {
			String imgPath = args[0];
			String des = args[1];
			if (imgPath.startsWith("http://")) {
				mStatusesAPI.uploadUrlText(des, imgPath, null, null, null,
						mListener);
			} else {
				Bitmap bmp = getSinaBitmap(imgPath);
				if (bmp != null) {
					mStatusesAPI.upload(des, bmp, null, null, mListener);
				} else {
					Toast.makeText(mContext, "Image not exist or Bitmap error",
							Toast.LENGTH_SHORT).show();
				}
			}
		}

	}

	/*
	 * 清除用户信息，切换用户授权
	 */
	public void cleanUserInfo(String[] params) {
		if (params.length == 0) {
			AccessTokenKeeper.clear(mContext);
			mAccessToken = null;
			mStatusesAPI = null;
			CookieManager.getInstance().removeAllCookie(); // 退出
		}
	}

	private Bitmap getSinaBitmap(String path) {
		Log.i(TAG, "getSinaBitmap " + path);
		if (TextUtils.isEmpty(path)) {
			return null;
		}

		if (path.startsWith("/")) {
			return BitmapFactory.decodeFile(path);
		} else {
			InputStream is;
			is = BUtility.getInputStreamByResPath(mContext, path);
			return BitmapFactory.decodeStream(is);
		}
	}

	public String getAbsPath(String path) {
		return BUtility.makeRealPath(path,
				this.mBrwView.getCurrentWidget().m_widgetPath,
				this.mBrwView.getCurrentWidget().m_wgtType);
	}

	private void auth(Context mContext, String appKey, String redirectUrl,
			String scope) {
		// 创建微博实例
		mWeiboAuth = new WeiboAuth(mContext, appKey, redirectUrl, Constants.SCOPE);
		mWeiboAuth.anthorize(new AuthListener());
	}
	
	/**
	 * 微博认证授权回调类。 1. SSO 授权时，需要在 {@link #onActivityResult} 中调用
	 * {@link SsoHandler#authorizeCallBack} 后， 该回调才会被执行。 2. 非 SSO
	 * 授权时，当授权结束后，该回调就会被执行。 当授权成功后，请保存该 access_token、expires_in、uid 等信息到
	 * SharedPreferences 中。
	 */
	class AuthListener implements WeiboAuthListener {

		@Override
		public void onComplete(Bundle values) {
			token = values.getString("access_token");
			openId = values.getString("uid");
			// 从 Bundle 中解析 Token
			mAccessToken = Oauth2AccessToken.parseAccessToken(values);
			if (mAccessToken.isSessionValid()) {
				// 显示 Token

				// 保存 Token 到 SharedPreferences
				AccessTokenKeeper.writeAccessToken(mContext, mAccessToken);
				mStatusesAPI = new StatusesAPI(mAccessToken);
				AccessTokenKeeper.writeToken(mContext, token);
				AccessTokenKeeper.writeOpenId(mContext, openId);
				if(isLogin) {
					jsCallback(CALLBACK_LOGIN_STATUS, 0, EUExCallback.F_C_INT, data2Json(mAccessToken));
					isLogin = false;
				}else {
					jsCallback(CALLBACK_GET_REGISTER_STATUS, 0, EUExCallback.F_C_INT, EUExCallback.F_C_SUCCESS);
					jsCallback(cbRegisterAppFunName, 0, EUExCallback.F_C_INT, EUExCallback.F_C_SUCCESS);
				}
			} else {
				// 以下几种情况，您会收到 Code：
				// 1. 当您未在平台上注册的应用程序的包名与签名时；
				// 2. 当您注册的应用程序包名与签名不正确时；
				// 3. 当您在平台上注册的包名和签名与您当前测试的应用的包名和签名不匹配时。
				String code = values.getString("code");
				String message = mContext.getString(EUExUtil.getResStringID("weibosdk_demo_toast_auth_failed"));
				if (!TextUtils.isEmpty(code)) {
					message = message + "\nObtained the code: " + code;
				}
				if(isLogin) {
					jsCallback(CALLBACK_LOGIN_STATUS, 0, EUExCallback.F_C_INT, code);
					isLogin = false;
				}else {
					jsCallback(CALLBACK_GET_REGISTER_STATUS, 0, EUExCallback.F_C_INT, code);
					jsCallback(cbRegisterAppFunName, 0, EUExCallback.F_C_INT, code);
				}
				
			}
		}

		@Override
		public void onCancel() {
			Toast.makeText(mContext, EUExUtil.getResStringID("weibosdk_demo_toast_auth_canceled"), Toast.LENGTH_LONG).show();
		}

		@Override
		public void onWeiboException(WeiboException e) {
			jsCallback(CALLBACK_GET_REGISTER_STATUS, 0, EUExCallback.F_C_INT,
			        EUExCallback.F_C_FAILED);
			jsCallback(cbRegisterAppFunName, 0, EUExCallback.F_C_INT,
			        EUExCallback.F_C_FAILED);
		}
	}
	
	private String data2Json(Oauth2AccessToken mAccessToken) {
		JSONObject obj = new JSONObject();
		try {
			Log.v("SSSSSS", mAccessToken.toString());
			obj.put("uid", mAccessToken.getUid());
			obj.put("expires_in", mAccessToken.getExpiresTime());
			obj.put("access_token", mAccessToken.getToken());
			obj.put("refresh_token", mAccessToken.getRefreshToken());
		} catch (JSONException e) {
			e.printStackTrace();
			return "";
		}
		return obj.toString();
	}
	
	/**
	 * 微博 OpenAPI 回调接口。
	 */
	private RequestListener mListener = new RequestListener() {
		@Override
		public void onComplete(String response) {
			if (!TextUtils.isEmpty(response)) {
				Log.d(TAG, "RequestComplete==" + response);
				if (response.startsWith("{\"created_at\"")) {
					// 调用 Status#parse 解析字符串成微博对象
					Status status = Status.parse(response);
					jsCallback(CALLBACK_SHARE_STATUS, 0, EUExCallback.F_C_INT,
					        EUExCallback.F_C_SUCCESS);
				} else {
					jsCallback(CALLBACK_SHARE_STATUS, 0, EUExCallback.F_C_INT,
					        EUExCallback.F_C_FAILED);
				}
			}
		}

		@Override
		public void onWeiboException(WeiboException e) {
			LogUtil.e(TAG, e.getMessage());
			Log.e(TAG, "onWeiboException" + e.getMessage());
			ErrorInfo info = ErrorInfo.parse(e.getMessage());
			String errCode = info.error_code;
			jsCallback(CALLBACK_SHARE_STATUS, 0, EUExCallback.F_C_INT, errCode);
		}
	};

	@Override
	protected boolean clean() {
		return true;
	}

    @Override
    public void onHandleMessage(Message message) {
        if(message == null){
            return;
        }
        Bundle bundle=message.getData();
        switch (message.what) {

            case MSG_REGISTER_APP:
                registerAppMsg(bundle.getStringArray(BUNDLE_DATA));
                break;
            case MSG_LOGIN:
                loginMsg(bundle.getStringArray(BUNDLE_DATA));
                break;
            default:
                super.onHandleMessage(message);
        }
    }
}
