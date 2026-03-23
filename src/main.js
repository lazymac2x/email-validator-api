const { Actor } = require("apify");
const { validateEmail, validateBatch, checkDomain, suggestFix } = require("./validator");

Actor.main(async () => {
  const input = await Actor.getInput();

  if (!input) {
    throw new Error("No input provided. Provide { mode, email/emails/domain }.");
  }

  const mode = input.mode || "validate";
  let result;

  switch (mode) {
    case "validate":
      if (!input.email) throw new Error('mode "validate" requires "email" field');
      result = await validateEmail(input.email);
      break;

    case "batch":
      if (!Array.isArray(input.emails)) throw new Error('mode "batch" requires "emails" array');
      result = await validateBatch(input.emails);
      break;

    case "domain":
      if (!input.domain) throw new Error('mode "domain" requires "domain" field');
      result = await checkDomain(input.domain);
      break;

    case "suggest":
      if (!input.email) throw new Error('mode "suggest" requires "email" field');
      result = suggestFix(input.email);
      break;

    default:
      throw new Error(`Unknown mode: ${mode}. Use: validate, batch, domain, suggest`);
  }

  await Actor.pushData(result);
  console.log("Result:", JSON.stringify(result, null, 2));
});
