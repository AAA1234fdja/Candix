import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "CANDIX",
  version: packageJson.version,
  copyright: `© ${currentYear}, CANDIX.`,
  meta: {
    title: "CANDIX — Autonomous Penetration Testing Console",
    description: "Console for the LLM-driven autonomous penetration testing system",
  },
};
