#!/usr/bin/python3

import argparse
import os
import subprocess as sp
import re

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
    def __init__(self, mainline_repo: GitRepo):
        self.mainline_repo = mainline_repo
        self.buglink_cache = [] # stores valid buglink urls

    def check_commit(self, commit: GitCommit):
        print(f'>>> Processing commit {commit.short_sha}: \"{commit.subject}\"')

        results = [
            self.check_buglink(commit),
            self.check_provenance(commit),
            self.check_signoff(commit),
        ]

        return all(results)

    def check_buglink(self, commit: GitCommit) -> bool:
        BUGLINK_PATTERN = r'^BugLink: ([^ ]+)$'
        message_lines = commit.message.splitlines()

        line_match = match_and_idx(message_lines, re.compile(BUGLINK_PATTERN, re.IGNORECASE))
        if not line_match:
            print('No BugLink found')
            return False

        ret = True
        line_idx, buglink_match = line_match
        buglink = buglink_match.group(1)

        if line_idx != 2:
            print('BugLink not on correct line')
            ret = False

        if not re.compile(BUGLINK_PATTERN).match(message_lines[line_idx]):
            print('BugLink does not match format \"BugLink: <URL>\"')
            ret = False

        if 'launchpad' not in buglink:
            print('BugLink is not a Launchpad link')
            ret = False
        elif buglink not in self.buglink_cache:
            status_code = int(sp.run(
                f'curl -I -s -o /dev/null -w \"%{{http_code}}\" buglink',
                stdout=sp.PIPE, stderr=sp.DEVNULL, shell=True
            ).stdout.decode('utf-8'))

            if status_code >= 400:
                print('Invalid BugLink')
            else:
                self.buglink_cache.append(buglink)

        return ret

    def check_provenance(self, commit: GitCommit) -> bool:
        message_lines = commit.message.splitlines()
        if re.compile(r'^(NVIDIA|UBUNTU): SAUCE:').match(commit.subject):
            return True # sauce patch, no upstream provenance

        line_match = match_and_idx(message_lines, re.compile(r'(cherry.?pick|back.?port).*\s([a-z0-9]+)\)?$'))
        if not line_match:
            print('Upstream commit but no cherry pick found')
            return False

        line_idx, cp_match = line_match
        cp_sha = cp_match.group(2)
        try:
            upstream_commit = GitCommit(self.mainline_repo, cp_sha)
        except ValueError as e:
            print('Upstream commit %s not found' % upstream_commit.sha)
            print(e)
            return False

        if commit.subject != upstream_commit.subject:
            print('Commits do not match')
            return False

        ret = True

        if commit.author_name != upstream_commit.author_name \
            and commit.author_email != upstream_commit.author_email:
            print('Commit authors do not match')
            ret = False

        if commit.date != upstream_commit.date:
            print('Commit dates do not match')
            ret = False

        if upstream_commit.body not in commit.body:
            print('Original commit message body has been modified')
            ret = False

        upstream_lines = upstream_commit.message.splitlines()
        if not (
            (message_lines[line_idx-1].strip() == "" and message_lines[line_idx-2] == upstream_lines[-1])
            or message_lines[line_idx-1] == upstream_lines[-1]
        ):
            print('Provenance message should occur after original message'
                  + ' and before the applier signoff, optionally preceded by a newline')
            ret = False

        return ret

    def check_signoff(self, commit: GitCommit) -> bool:
        if f'{commit.author_name} <{commit.author_email}>' not in commit.message:
            print('No signoff from author')
            return False
        return True


def main():
    parser = argparse.ArgumentParser(
        prog='patchbot.py',
        description='Performs basic checks on Nvidia patch formatting',
    )
    parser.add_argument('-r', '--patch-repo', default='.',
                        help='Path to the repo with the patches')
    parser.add_argument('-m', '--mainline-repo', default=f'{os.path.expanduser("~")}/linux/linux_mainline',
                        help='Path to Linux mainline repo')
    parser.add_argument('base_ref',
                        help='Ref of the base where patches are applied on top of')
    parser.add_argument('patch_ref',
                        help='Ref of tip of patches')

    args = parser.parse_args()

    repo = GitRepo(args.patch_repo)
    commits = [
        GitCommit(repo, sha) for sha in
        repo.run_stdout(['log', '--format=%H', f'{args.base_ref}..{args.patch_ref}'])[0].splitlines()
    ]

    checker = CommitChecker(GitRepo(args.mainline_repo))
    num_pass = 0
    for commit in commits:
        if checker.check_commit(commit):
            num_pass += 1

    print(f'Results {num_pass}/{len(commits)} patches passed')

def match_and_idx(lines: list[str], pattern: re.Pattern) -> tuple[int, re.Match] | None:
    for i, line in enumerate(lines):
        line_match = pattern.search(line)
        if line_match:
            return (i, line_match)
    return None

if __name__ == '__main__':
    main()
