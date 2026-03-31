package ubuntu

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

const (
	defaultGitURL    = "git://git.launchpad.net/ubuntu-cve-tracker"
	defaultGitBranch = "master"
	repoDirName      = "ubuntu-cve-tracker"
)

type GitManager struct {
	url    string
	branch string
	dest   string
	logger *slog.Logger
}

func NewGitManager(workspace, url, branch string, logger *slog.Logger) *GitManager {
	if url == "" {
		url = defaultGitURL
	}
	if branch == "" {
		branch = defaultGitBranch
	}
	return &GitManager{
		url:    url,
		branch: branch,
		dest:   filepath.Join(workspace, "input", repoDirName),
		logger: logger,
	}
}

func (g *GitManager) Exists() bool {
	_, err := os.Stat(filepath.Join(g.dest, ".git"))
	return err == nil
}

func (g *GitManager) Clone(ctx context.Context) error {
	inputDir := filepath.Dir(g.dest)
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return fmt.Errorf("create input directory: %w", err)
	}

	g.logger.Info("cloning ubuntu-cve-tracker repository", "url", g.url, "branch", g.branch, "dest", g.dest)

	_, err := git.PlainCloneContext(ctx, g.dest, false, &git.CloneOptions{
		URL:           g.url,
		ReferenceName: plumbing.ReferenceName("refs/heads/" + g.branch),
		SingleBranch:  true,
		Depth:         1,
	})
	if err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	return nil
}

func (g *GitManager) Pull(ctx context.Context) error {
	g.logger.Info("pulling latest changes for ubuntu-cve-tracker repository")

	repo, err := git.PlainOpen(g.dest)
	if err != nil {
		g.logger.Warn("failed to open repo, re-cloning", "error", err)
		if rmErr := os.RemoveAll(g.dest); rmErr != nil {
			return fmt.Errorf("open repo failed and could not remove dir: open=%w, rm=%v", err, rmErr)
		}
		return g.Clone(ctx)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		g.logger.Warn("failed to get worktree, re-cloning", "error", err)
		if rmErr := os.RemoveAll(g.dest); rmErr != nil {
			return fmt.Errorf("worktree failed and could not remove dir: wt=%w, rm=%v", err, rmErr)
		}
		return g.Clone(ctx)
	}

	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset}); err != nil {
		g.logger.Warn("git reset failed, re-cloning", "error", err)
		if rmErr := os.RemoveAll(g.dest); rmErr != nil {
			return fmt.Errorf("reset failed and could not remove dir: reset=%w, rm=%v", err, rmErr)
		}
		return g.Clone(ctx)
	}

	if err := repo.DeleteRemote("origin"); err != nil {
		g.logger.Warn("failed to delete remote origin", "error", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{g.url},
	}); err != nil {
		g.logger.Warn("failed to set remote url, re-cloning", "error", err)
		if rmErr := os.RemoveAll(g.dest); rmErr != nil {
			return fmt.Errorf("set remote failed and could not remove dir: remote=%w, rm=%v", err, rmErr)
		}
		return g.Clone(ctx)
	}

	if err := worktree.Checkout(&git.CheckoutOptions{
		Branch: plumbing.ReferenceName("refs/heads/" + g.branch),
		Force:  true,
	}); err != nil {
		g.logger.Warn("git checkout failed, re-cloning", "error", err)
		if rmErr := os.RemoveAll(g.dest); rmErr != nil {
			return fmt.Errorf("checkout failed and could not remove dir: checkout=%w, rm=%v", err, rmErr)
		}
		return g.Clone(ctx)
	}

	err = worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.ReferenceName("refs/heads/" + g.branch),
		SingleBranch:  true,
		Depth:         1,
		Force:         true,
	})
	if err != nil {
		g.logger.Warn("git pull failed, re-cloning", "error", err)
		if rmErr := os.RemoveAll(g.dest); rmErr != nil {
			return fmt.Errorf("git pull failed and could not remove dir: pull=%w, rm=%v", err, rmErr)
		}
		return g.Clone(ctx)
	}

	return nil
}

func (g *GitManager) EnsureRepo(ctx context.Context) error {
	if g.Exists() {
		return g.Pull(ctx)
	}
	return g.Clone(ctx)
}

func (g *GitManager) RepoPath() string {
	return g.dest
}

func (g *GitManager) URL() string {
	return g.url
}
