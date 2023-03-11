import { getChannelInfo } from "yt-channel-info"
import { BrowserContext } from "playwright-core"
import { getYoutubeChannelId } from "./utils"
import {
  getTwitterFollowerCountWithBrowser,
  getTwitterFollowerCountWithEmbedApi,
} from "./twitter"
import { getIgFollowerCount, getIgSessionId } from "./instagram"
import { fetchEnhanced } from "./fetch"

export type Options =
  | {
    type: "instagram"
    username: string
    sessionId: string
  }
  | {
    type: "youtube"
    /** Channel ID or channel URL (https://www.youtube.com/c/CHANNEL_ID) */
    channel: string
  }
  | {
    type: "tiktok"
    username: string
  }
  | {
    type: "twitter"
    username: string
    /**
     * A playwright chromium browser context
     * @example
     * ```js
     * import { getBrowserContext, destroyBrowser } from "follower-count"
     * await getFollowerCount({
     *   type: "twitter",
     *   username: "cristiano",
     *   browserContext: getBrowserContext({ chromiumPath: "/path/to/chromium" }),
     * })
     * await destroyBrowser()
     * ```
     */
    browserContext?: BrowserContext
  }

export const getFollowerCount = async (options: Options): Promise<number> => {
  if (options.type === "instagram") {
    return getInstagramFollowerCount(options.username, options.sessionId)
  }

  if (options.type === "youtube") {
    return getYoutubeFollowerCount(options.channel)
  }

  if (options.type === "tiktok") {
    return getTikTokFollowerCount(options.username)
  }

  if (options.type === "twitter") {
    return options.browserContext
      ? getTwitterFollowerCountWithBrowser(
        options.username,
        options.browserContext,
      )
      : getTwitterFollowerCountWithEmbedApi(options.username)
  }

  throw new Error(`Unknown type: ${(options as any).type}`)
}

export async function getInstagramFollowerCount(
  username: string,
  sessionId: string,
) {
  return getIgFollowerCount(username, sessionId)
}

export async function getYoutubeFollowerCount(channel: string) {
  const info = await getChannelInfo({
    channelId: getYoutubeChannelId(channel),
  })
  // Not sure why subscriberCount might be a float
  return Math.floor(info.subscriberCount)
}

export async function getTikTokFollowerCount(username: string) {
  const text = await fetchEnhanced(
    `https://www.tiktok.com/@${username}`,
    {},
  ).then((res) => res.text())

  const authorStatsMatch = /"authorStats":\{[^}]*\}/.exec(text);

  const authorStatsObject = JSON.parse(`{${authorStatsMatch[0]}}`);

  const m2 = authorStatsObject.authorStats.followerCount;

  const following = authorStatsObject.authorStats.followingCount

  const count = authorStatsObject.authorStats.videoCount

  return {
    'followers': m2 ? parseInt(m2) : 0,
    'following': following ? parseInt(following) : 0,
    'count': count ? parseInt(count) : 0
  }
}

export * from "./browser"

export { isFetchError } from "./fetch"

export {
  getIgSessionId,
  getTwitterFollowerCountWithBrowser,
  getTwitterFollowerCountWithEmbedApi,
}
