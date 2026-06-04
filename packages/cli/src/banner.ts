export const AGENTCSP_BANNER = String.raw`
    ___                    __  __________
   /   | ____ ____  ____  / /_/ ____/ ___/____
  / /| |/ __ '/ _ \/ __ \/ __/ /    \__ \/ __ \
 / ___ / /_/ /  __/ / / / /_/ /___ ___/ / /_/ /
/_/  |_\__, /\___/_/ /_/\__/\____//____/ .___/
      /____/                           /_/

  [ context ]==>[ surface ]==>[ capability ]==>[ control ]
       trust        data class        authority       evidence
`;

const cyan = "\x1b[36m";
const green = "\x1b[32m";
const dim = "\x1b[2m";
const reset = "\x1b[0m";

export function renderBanner(options: { color?: boolean } = {}): string {
  if (!options.color) return AGENTCSP_BANNER;
  return AGENTCSP_BANNER.split("\n")
    .map((line) => {
      if (line.includes("[ context ]")) return `${green}${line}${reset}`;
      if (line.includes("trust")) return `${dim}${line}${reset}`;
      return `${cyan}${line}${reset}`;
    })
    .join("\n");
}

export async function printBanner(options: { animate?: boolean } = {}): Promise<void> {
  const shouldAnimate =
    Boolean(options.animate) &&
    Boolean(process.stdout.isTTY) &&
    process.env.CI !== "true" &&
    process.env.AGENTCSP_NO_ANIMATION !== "1";

  if (!shouldAnimate) {
    console.log(renderBanner({ color: Boolean(process.stdout.isTTY) }));
    return;
  }

  const lines = renderBanner({ color: true }).split("\n");
  for (const line of lines) {
    process.stdout.write(`${line}\n`);
    await sleep(18);
  }
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
