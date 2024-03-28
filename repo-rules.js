const { Octokit } = require("@octokit/rest");

const token = (process.env.PAT || '').trim();
const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');

(async () => {
    const fetch = (await import('node-fetch')).default;

    const octokit = new Octokit({
        auth: token,
        request: {
            fetch: fetch
        }
    });

    async function applyProtection(branch) {
        await octokit.repos.updateBranchProtection({
            owner,
            repo,
            branch,
            required_status_checks: {
                strict: true,
                contexts: []
            },
            enforce_admins: true,
            required_pull_request_reviews: {
                dismissal_restrictions: {},
                dismiss_stale_reviews: true,
                require_code_owner_reviews: true,
                required_approving_review_count: 0
            },
            restrictions: {
                users: ["prometheusaiolos"],
                teams: []
            }
        });
        console.log(`Branch protection applied to ${branch}`);
    }

    ['dev', 'uat', 'main'].forEach(branch => applyProtection(branch));
})();
