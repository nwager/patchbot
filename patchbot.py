#!/usr/bin/python3

import argparse
import os
import subprocess as sp
import re

# Pass/fail result and a list of reasons (can be empty)
Result = tuple[bool, list[str]]

class GitRepo:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        if not self.run_check(['rev-parse', '--git-dir'])[0]:
            raise ValueError(f'{self.repo_path} is not a git directory')

    def run(self, cmd: list[str], **kwargs) -> sp.CompletedProcess[bytes]:
        return sp.run(['git', *cmd], cwd=self.repo_path, **kwargs)

    def run_check(self, cmd: list[str]) -> tuple[bool, sp.CompletedProcess[bytes]]:
        completed = self.run(
            cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL
        )
        return completed.returncode == 0, completed

    def run_stdout(self, cmd: list[str]) -> tuple[str, sp.CompletedProcess[bytes]]:
        completed = self.run(cmd, stdout=sp.PIPE, stderr=sp.DEVNULL)
        return completed.stdout.decode('utf-8'), completed

class GitCommit:
    def __init__(self, repo: GitRepo, sha: str):
        self.repo = repo
        if not repo.run_check(['show', '--no-decorate', sha])[0]:
            raise ValueError(f'Commit {sha} does not exist in repo {repo.repo_path}')

        def log_format(format):
            return self.repo.run_stdout(['log', f'--format={format}', '-n 1', sha])[0].strip()

        self.sha = log_format(r'%H')
        self.short_sha = log_format(r'%h')
        self.author_name = log_format(r'%an')
        self.author_email = log_format(r'%ae')
        self.date = log_format(r'%ad')
        self.message = log_format(r'%B')
        self.subject = log_format(r'%s')
        self.body = log_format(r'%b')

class CommitChecker:
    def __init__(self, mainline_repo: GitRepo, ignore_buglink=False):
        self.mainline_repo = mainline_repo
        self.buglink_cache = [] # stores valid buglink urls
        self.ignore_buglink = ignore_buglink

    def check_commit(self, commit: GitCommit) -> tuple[bool, list[str]]:
        print(f'>>> Processing commit {commit.short_sha}: \"{commit.subject}\"')

        results = [
            self.check_buglink(commit),
            self.check_provenance(commit),
            self.check_signoff(commit),
            self.check_fixes(commit),
            self.check_upstream_fixed_by(commit),
        ]

        status = all(r[0] for r in results)
        # flatten list of reasons
        reasons = []
        for r_list in [r[1] for r in results]:
            if r_list:
                reasons.append(*r_list)

        return (all(r[0] for r in results), reasons)

    def check_buglink(self, commit: GitCommit) -> Result:
        reasons = []
        if self.ignore_buglink:
            return (True, reasons)

        # Embargoed patches can't have public bugs, so they don't need a BugLink
        if re.compile(r'^(EMBARGOED|\[EMBARGOED\])').search(commit.subject):
            return (True, reasons)

        BUGLINK_PATTERN = r'^BugLink: ([^ ]+)$'
        message_lines = commit.message.splitlines()

        line_match = match_and_idx(message_lines, re.compile(BUGLINK_PATTERN, re.IGNORECASE))
        if not line_match:
            reasons.append('No BugLink found')
            return (False, reasons)

        ret = True
        line_idx, buglink_match = line_match
        buglink = buglink_match.group(1)

        if line_idx != 2:
            reasons.append('BugLink not on correct line')
            ret = False

        if not re.compile(BUGLINK_PATTERN).match(message_lines[line_idx]):
            reasons.append('BugLink does not match format \"BugLink: <URL>\"')
            ret = False

        if 'launchpad' not in buglink:
            reasons.append('BugLink is not a Launchpad link')
            ret = False
        elif buglink not in self.buglink_cache:
            status_code = int(sp.run(
                f'curl -I -s -o /dev/null -w \"%{{http_code}}\" {buglink}',
                stdout=sp.PIPE, stderr=sp.DEVNULL, shell=True
            ).stdout.decode('utf-8'))

            if status_code >= 400:
                reasons.append('Invalid BugLink')
                ret = False
            else:
                self.buglink_cache.append(buglink)

        return (ret, reasons)

    def check_provenance(self, commit: GitCommit) -> Result:
        reasons = []
        message_lines = commit.message.splitlines()
        if re.compile(r'(NVIDIA|UBUNTU):').search(commit.subject):
            return (True, reasons) # sauce or other Ubuntu-specific patch, no upstream provenance

        if re.compile(r'((NVIDIA:|SAUCE:) )?Revert').search(commit.subject):
            return (True, reasons) # Revert patch, doesn't need provenance

        # Ignore nvbug links
        while True:
            # TODO: Looping all of this is less efficient than just having
            #       match_and_idx return ALL matching indices
            nvbug_match = match_and_idx(message_lines, re.compile(r'(http|https)://nvbug.*'))
            if nvbug_match:
                line_idx = nvbug_match[0]
                message_lines.pop(line_idx)
                # Remove trailing newline if needed
                if len(message_lines) > line_idx and not message_lines[line_idx].strip():
                    message_lines.pop(line_idx)
            else:
                break

        # Reconstruct commit message after trimming ignored lines
        cleaned_message = '\n'.join(message_lines)

        line_match = match_and_idx(message_lines, re.compile(r'^\((cherry picked|backported) from commit ([a-z0-9]+)( (.*))?\)$'))

        if not line_match:
            reasons.append('Upstream commit but no cherry pick found')
            return (False, reasons)

        line_idx, prov_match = line_match
        prov_type = prov_match.group(1)
        prov_sha = prov_match.group(2)
        prov_repo = prov_match.group(4)

        if prov_repo and prov_repo not in ['linux-next']:
            reasons.append(f'NOTE: Commit {prov_type} from non-mainline repo {prov_repo}. Manual verification required.')
            return (True, reasons)
        else:
            try:
                upstream_commit = GitCommit(self.mainline_repo, prov_sha)
            except ValueError as e:
                reasons.append('Upstream commit %s not found' % upstream_commit.sha)
                print(e)
                return (False, reasons)

        if commit.subject != upstream_commit.subject:
            reasons.append('Commits do not match')
            return (False, reasons)

        ret = True

        if commit.author_name != upstream_commit.author_name \
            and commit.author_email != upstream_commit.author_email:
            reasons.append('Commit authors do not match')
            ret = False

        if commit.date != upstream_commit.date:
            reasons.append('Commit dates do not match')
            ret = False

        if upstream_commit.body not in cleaned_message:
            reasons.append('Original commit message body has been modified')
            ret = False

        upstream_lines = upstream_commit.message.splitlines()
        if not (
            (message_lines[line_idx-1].strip() == "" and message_lines[line_idx-2] == upstream_lines[-1])
            or message_lines[line_idx-1] == upstream_lines[-1]
        ):
            reasons.append('Provenance message should occur after original message'
                  + ' and before the applier signoff, optionally preceded by a newline')
            ret = False

        return (ret, reasons)

    def check_signoff(self, commit: GitCommit) -> Result:
        reasons = []
        # Only check for email because sometimes the author name differs from the SOB
        if f'<{commit.author_email}>' not in commit.message:
            reasons.append('No signoff from author')
            return (False, reasons)
        return (True, reasons)

    def check_fixes(self, commit: GitCommit) -> Result:
        reasons = []

        num_fixes = len(re.compile(r'^Fixes:', re.MULTILINE).findall(commit.message))

        FIXES_PATTERN = r'^Fixes: ([a-fA-F0-9]+) \(\"(.*)\"\)$'
        fixes = re.compile(FIXES_PATTERN, re.MULTILINE).findall(commit.message)

        if num_fixes != len(fixes):
            reasons.append('Some "Fixes:" lines may be malformed')

        r = True
        for f in fixes:
            sha, subject = f
            output, error = commit.repo.run_stdout(
                    ['log', '--max-count', '1', '--grep', f'^{re.escape(subject)}']
                    )
            if not output:
                r = False
                reasons.append(f'Unsatisfied "Fixes: {sha} ("{subject}")"')

        return (r, reasons)

    def check_upstream_fixed_by(self, commit: GitCommit) -> Result:
        reasons = []

        if 'SAUCE:' in commit.subject:
            # SAUCE commits will not have upstream fixes
            return (True, reasons)

        output, _error = self.mainline_repo.run_stdout(
                ['log', 'master', '--format=%H', '--grep', f'Fixes:.*{re.escape(commit.subject)}']
                )
        output = output.strip().splitlines()
        if not output:
            return (True, reasons)

        for sha in output:
            try:
                fixer = GitCommit(self.mainline_repo, sha)
            except ValueError as e:
                print('Fixer commit SHA is not a valid commit')
                raise e

            reasons.append(f'Fixed by: {fixer.short_sha} ("{fixer.subject}")')

        return (False, reasons)

def main():
    parser = argparse.ArgumentParser(
        prog='patchbot.py',
        description='Performs basic checks on Nvidia patch formatting',
    )
    parser.add_argument('-r', '--patch-repo', default='.',
                        help='Path to the repo with the patches')
    parser.add_argument('-m', '--mainline-repo', default=f'{os.path.expanduser("~")}/linux/mainline',
                        help='Path to Linux mainline repo')
    parser.add_argument('base_ref',
                        help='Ref of the base where patches are applied on top of')
    parser.add_argument('patch_ref',
                        help='Ref of tip of patches')
    parser.add_argument('--ignore-buglink', action='store_true',
                        help='Don\'t check for BugLinks')

    args = parser.parse_args()

    repo = GitRepo(args.patch_repo)
    commits = [
        GitCommit(repo, sha) for sha in
        repo.run_stdout(['log', '--format=%H', f'{args.base_ref}..{args.patch_ref}'])[0].splitlines()
    ]

    checker = CommitChecker(GitRepo(args.mainline_repo), ignore_buglink=args.ignore_buglink)
    num_pass = 0
    failed: list[tuple[GitCommit, Result]] = []
    for commit in commits:
        result = checker.check_commit(commit)
        if result[0]:
            num_pass += 1
        else:
            failed.append((commit, result))
        for r in result[1]:
            print(r)

    print(f'Results {num_pass}/{len(commits)} patches passed')

    if failed:
        print(f'\nFailed patches:')
        for c, r in failed:
            print(f'{c.short_sha} ("{c.subject}")')
            for reason in r[1]:
                print('    ' + reason)

def match_and_idx(lines: list[str], pattern: re.Pattern) -> tuple[int, re.Match] | None:
    for i, line in enumerate(lines):
        line_match = pattern.search(line)
        if line_match:
            return (i, line_match)
    return None

if __name__ == '__main__':
    main()
