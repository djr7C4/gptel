---
name: update-gptel-models
description: Retrieve information on new models and update the gptel code
---

Use the following process to update models for gptel. Only look for new OpenAI,
Anthropic, Gemini and DeepSeek models. Don't worry about other providers. Apply
the following steps for each provider in a new branch (based on master) for the
models being added for that provider. The branch name should be descriptive
(e.g. openai-gpt-5.6). Don't run any tests.

1. Determine the list of known models for the provider. This can be done by
   looking at the model definitions in the appropriate file
   (e.g. gptel-openai.el for OpenAI).

2. Access information about the new models from the provider's website that were
   not found in the gptel model defintions. For OpenAI, use
   https://developers.openai.com/api/docs/models. For Anthropic, use
   https://platform.claude.com/docs/en/about-claude/models/overview. For Gemini,
   use https://ai.google.dev/gemini-api/docs/models. For DeekSeek, use
   https://api-docs.deepseek.com/quick_start/pricing/.

   The full gptel description of a model looks like

```elisp
(gpt-5.6-sol
     :description "The best model for coding and agentic tasks"
     :capabilities (media tool-use json url responses-api)
     :reasoning-effort (member none low medium high xhigh max)
     :mime-types ("image/jpeg" "image/png" "image/gif" "image/webp")
     :context-window 1050
     :input-cost 5
     :output-cost 30
     :cutoff-date "2026-02")
 ```

   Reasoning effort information is available at
   https://developers.openai.com/api/docs/guides/reasoning for OpenAI,
   https://platform.claude.com/docs/en/build-with-claude/adaptive-thinking for
   Anthropic, https://ai.google.dev/gemini-api/docs/thinking for Gemini and
   https://api-docs.deepseek.com/guides/thinking_mode/ for DeepSeek.

   If any information is missing, perform web searches to attempt to locate
   it. Never guess for information that you are unable to find. Instead, do your
   best and let the user know what you were not able to find.

3. Add the information you discovered to the gptel variable in the appropriate
   file (e.g. gptel-openai.el for OpenAI). Make sure to follow these rules.

   1. The default model is the first OpenAI model in the list. This should not
      be updated unless there is a newer model of similar cost. If no such model
      exists, keep the current cost. The rule takes priority over rule 3.2.

   2. Models from the same series should be adjacent in the list with more
      powerful models listed first. For example, gpt-5.4-pro, gpt-5.4,
      gpt-5.4-mini and lastly gpt-5.4-nano. The exception is rule 3.1 which
      takes priority.

   3. Never change older entries in the list even if you think that there are
      errors. Inform the user instead.

   4. Don't include reasoning effort. This needs to be added later when these
      branches are merged into the reasoning-effort branch instead.

4. Commit the branch (but do not push).

5. Merge the branch into the reasoning-effort branch. Make sure not to remove
   existing reasoning effort information from the model definitions. Add
   reasoning effort defintions for the new models but do not change anything
   else.

6. Commit the changes to the reasoning effort branch separately for each
   provider that had new models added.

7. Merge the reasoning-effort branch into the dev branch.
