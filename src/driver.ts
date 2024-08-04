/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| Make sure you through the code and comments properly and make necessary
| changes as per the requirements of your implementation.
|
*/

/**
 |--------------------------------------------------------------------------
 *  Search keyword "YourDriver" and replace it with a meaningful name
 |--------------------------------------------------------------------------
 */

import { Oauth2Driver, RedirectRequest } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import type { AllyDriverContract, AllyUserContract, ApiRequestContract } from '@adonisjs/ally/types'

/**
 *
 * Access token returned by your driver implementation. An access
 * token must have "token" and "type" properties and you may
 * define additional properties (if needed)
 */
export type DeezerAccessToken = {
  token: string
  type: 'bearer'
}

/**
 * Scopes accepted by the driver implementation.
 */
export type DeezerScopes = string

/**
 * The configuration accepted by the driver implementation.
 */
export type DeezerConfig = {
  clientId: string
  clientSecret: string
  callbackUrl: string
  authorizeUrl?: string
  accessTokenUrl?: string
  userInfoUrl?: string
  scopes: DeezerScopes[]
}

/**
 * Driver implementation. It is mostly configuration driven except the API call
 * to get user info.
 */
export class DeezerDriver
  extends Oauth2Driver<DeezerAccessToken, DeezerScopes>
  implements AllyDriverContract<DeezerAccessToken, DeezerScopes> {

  protected authorizeUrl = 'https://connect.deezer.com/oauth/auth.php'
  protected accessTokenUrl = 'https://connect.deezer.com/oauth/access_token.php'

  protected userInfoUrl = 'https://api.deezer.com/user/me'

  /**
   * The param name for the authorization code.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error.
   */
  protected errorParamName = 'error_reason'

  /**
   * Cookie name for storing the CSRF token.
   */
  protected stateCookieName = 'deezer_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'perms'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ','

  constructor(
    ctx: HttpContext,
    public config: DeezerConfig
  ) {
    super(ctx, config)

    /**
     * Extremely important to call the following method to clear the
     * state set by the redirect request.
     *
     * DO NOT REMOVE THE FOLLOWING LINE
     */
    this.loadState()
  }

  /**
   * Optionally configure the authorization redirect request. The actual request
   * is made by the base implementation of "Oauth2" driver and this is a
   * hook to pre-configure the request.
   */
  protected configureRedirectRequest(request: RedirectRequest<DeezerScopes>) {
    request.scopes(this.config.scopes)

    request.param('app_id', this.config.clientId)
    request.param('redirect_uri', this.config.callbackUrl)

  }

  /**
   * Optionally configure the access token request. The actual request is made by
   * the base implementation of "Oauth2" driver and this is a hook to pre-configure
   * the request
   */

  // protected configureAccessTokenRequest(request: ApiRequest) {}

  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  accessDenied() {
    return this.ctx.request.input('error') === 'user_denied'
  }

  protected async getAuthenticatedRequest(token: string) {
    return this.httpClient(this.config.userInfoUrl || this.userInfoUrl).header('Authorization', `Bearer ${token}`)
  }

  protected async getUserInfo(
    token: string,
    callback?: (request: ApiRequestContract) => void
  ) {
    const request = await this.getAuthenticatedRequest(token)

    /**
     * Allow end user to configure the request. This should be called after your custom
     * configuration, so that the user can override them (if needed)
     */
    if (typeof callback === 'function') {
      callback(request)
    }

    const response = await request.get()
    const user = response.body

    return {
      id: user.id,
      nickName: user.name,
      name: user.name,
      email: user.email || null,
      emailVerificationState: 'unsupported',
      avatarUrl: user.picture,
      original: user
    }
  }

  /**
   * Get the user details by query the provider API. This method must return
   * the access token and the user details both. Checkout the google
   * implementation for same.
   *
   * https://github.com/adonisjs/ally/blob/develop/src/Drivers/Google/index.ts#L191-L199
   */
  async user(callback?: (request: ApiRequestContract) => void): Promise<AllyUserContract<DeezerAccessToken>> {
    const accessToken = await this.accessToken()
    const user = await this.getUserInfo(accessToken.token, callback)

    return {...user, token: accessToken} as AllyUserContract<DeezerAccessToken>
  }

  async userFromToken(accessToken: string, callback?: (request: ApiRequestContract) => void ): Promise<AllyUserContract<{ token: string; type: 'bearer' }>> {
    const user = await this.getUserInfo(accessToken, callback)

    return {...user, token: accessToken} as AllyUserContract<DeezerAccessToken>
  }
}

/**
 * The factory function to reference the driver implementation
 * inside the "config/ally.ts" file.
 */
export function DeezerDriverService(config: DeezerConfig): (ctx: HttpContext) => DeezerDriver {
  return (ctx) => new DeezerDriver(ctx, config)
}
