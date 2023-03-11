import { BrowserContext } from "playwright-core"
import { fetchEnhanced } from "./fetch"

export async function getTwitterFollowerCountWithEmbedApi(
  username: string,
): Promise<number> {
  return fetchEnhanced(
    `https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names=${username}&v=${Date.now()}`,
  )
    .then((res) => res.json())
    .then((data: any) => {
      if (data.length === 0) {
        throw new Error(`twitter user "${username}" does not exist`)
      }
      return data[0].followers_count
    })
}

export async function getTwitterFollowerCountWithBrowser(
  username: string,
  browserContext: BrowserContext,
) {
  const selectorFollowers = `a[href$="/followers"]`;
  const selectorFollowing = `a[href$="/following"]`;
  const page = await browserContext.newPage();
  await page.goto(`https://twitter.com/${username}`);
  await page.waitForSelector(selectorFollowers);
  const text = await page.evaluate((selector) => {
    const text2 = document.querySelector(selector).textContent || "";
    return text2.split(" ")[0];
  }, selectorFollowers);
  const text2 = await page.evaluate((selector) => {
    const text2 = document.querySelector(selector).textContent || "";
    return text2.split(" ")[0];
  }, selectorFollowing);
  const lastChar = text[text.length - 1].toLowerCase();
  const times = lastChar === "m" ? 1e6 : lastChar === "k" ? 1e3 : 1;
  const count = Number(text.replace(/[^.\d]+/g, "")) * times;

  const lastChar2 = text2[text2.length - 1].toLowerCase();
  const times2 = lastChar2 === "m" ? 1e6 : lastChar2 === "k" ? 1e3 : 1;
  const count2 = Number(text2.replace(/[^.\d]+/g, "")) * times2;
  await page.close();
  return {
    followers: count,
    following: count2
  };
}
