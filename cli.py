#!/usr/bin/env python3
"""
CLI tool for KuberFlow Dashboard

Persistent configuration (base_url + token) is stored in ~/.dockerflow_cli.json
"""

import click
import requests
import json
import os
from typing import Optional, Dict, List
from tabulate import tabulate

CONFIG_PATH = os.path.expanduser("~/.dockerflow_cli.json")
DEFAULT_BASE_URL = "http://localhost:8000"


def read_config() -> Dict[str, str]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            return {}
    return {}


def write_config(updates: Dict[str, Optional[str]]) -> None:
    cfg = read_config()
    for k, v in updates.items():
        if v is None:
            cfg.pop(k, None)
        else:
            cfg[k] = v
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f)
    os.replace(tmp, CONFIG_PATH)


def normalize_base_url(url: str) -> str:
    if not url:
        return url
    return url.rstrip("/")


class DockerFlowCLI:
    def __init__(self, base_url: Optional[str] = None):
        cfg = read_config()
        cfg_base = cfg.get("base_url")
        if base_url:
            self.base_url = normalize_base_url(base_url)
        elif cfg_base:
            self.base_url = normalize_base_url(cfg_base)
        else:
            self.base_url = DEFAULT_BASE_URL

        self.token = cfg.get("token")
        self.session = requests.Session()
        self._user_info = None

    def get_headers(self) -> Dict[str, str]:
        if not self.token:
            cfg = read_config()
            token = cfg.get("token")
            if token:
                self.token = token
            else:
                raise click.ClickException("Not authenticated. Please login first.")
        return {"Authorization": f"Bearer {self.token}"}

    def login(self, username: str, password: str) -> bool:
        try:
            data = {"username": username, "password": password}
            url = f"{self.base_url}/auth/login"
            response = self.session.post(url, data=data)
            if response.status_code == 200:
                payload = response.json()
                token = payload.get("access_token") or payload.get("token") or payload.get("accessToken")
                if not token:
                    click.echo("Login succeeded but no token was returned.")
                    return False
                self.token = token
                write_config({"token": self.token, "base_url": self.base_url})
                click.echo(f"Successfully logged in as {username}")
                self._user_info = None
                return True
            else:
                click.echo(f"Login failed: {response.status_code} {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")
            return False

    def logout(self):
        self.token = None
        write_config({"token": None})
        self._user_info = None
        click.echo("Logged out successfully")

    def status(self):
        click.echo(f"Base URL: {self.base_url}")
        if self.token:
            click.echo("Authenticated")
            info = self.get_user_info()
            if info:
                click.echo(f"Username: {info.get('username')}")
                click.echo(f"User ID: {info.get('id')}")
                click.echo(f"Project: {info.get('project')}")
                click.echo(f"Admin: {'Yes' if info.get('is_admin') else 'No'}")
            else:
                click.echo("Token present but user info unavailable")
        else:
            click.echo("Not authenticated")

    def get_user_info(self):
        if self._user_info is not None:
            return self._user_info
        try:
            headers = self.get_headers()
            url = f"{self.base_url}/auth/me"
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                self._user_info = response.json()
                return self._user_info
            else:
                return None
        except requests.exceptions.RequestException:
            return None

    def set_endpoint(self, url: str):
        normalized = normalize_base_url(url)
        write_config({"base_url": normalized})
        self.base_url = normalized
        click.echo(f"Endpoint set to: {normalized}")

    # ---------------- Images ----------------
    def get_images(self, group: Optional[str] = None, image_id: Optional[str] = None):
        headers = self.get_headers()
        try:
            if group and image_id:
                url = f"{self.base_url}/images/{group}/{image_id}"
            elif group:
                url = f"{self.base_url}/images/{group}"
            else:
                url = f"{self.base_url}/images"
            resp = self.session.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            return None
        except requests.exceptions.RequestException:
            return None

    # ---------------- Image Test Pipeline ----------------
    def get_image_test_pipeline(self, group: Optional[str] = None, deploy_id: Optional[str] = None):
        headers = self.get_headers()
        try:
            if group and deploy_id:
                url = f"{self.base_url}/image_test_pipeline/{group}/{deploy_id}"
            elif group:
                url = f"{self.base_url}/image_test_pipeline/{group}"
            else:
                url = f"{self.base_url}/image_test_pipeline"
            resp = self.session.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            return None
        except requests.exceptions.RequestException:
            return None

    # ---------------- Deployments ----------------
    def get_deployments(self, repo: Optional[str] = None):
        headers = self.get_headers()
        try:
            if repo:
                url = f"{self.base_url}/deploy/{repo}"
            else:
                url = f"{self.base_url}/deploy"
            resp = self.session.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            return None
        except requests.exceptions.RequestException:
            return None

    def deploy_image(self, project: str, repo_name: str, tag: str, hosts: Optional[List[str]] = None):
        """
        Queue a deployment for an image on cluster/clusters
        """
        headers = self.get_headers()
        payload = {
            "project": project,
            "repo_name": repo_name,
            "tag": tag,
        }
        if hosts:

            clean_hosts = [h for h in hosts if h and h.strip()]
            payload["hosts"] = clean_hosts

        try:
            url = f"{self.base_url}/deploy"
            resp = self.session.post(url, json=payload, headers=headers, timeout=30)
            if resp.status_code in (200, 201):
                data = resp.json()
                click.echo(f"Deployment queued (id: {data.get('deployment_id')})")
                if data.get("hosts"):
                    click.echo(f"Hosts: {', '.join(data.get('hosts'))}")
                return True
            else:
                click.echo(f"Failed to queue deployment: {resp.status_code} {resp.text}")
                return False
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")
            return False

    # ---------------- Repositories (new) ----------------
    def get_repositories(self):
        headers = self.get_headers()
        try:
            url = f"{self.base_url}/repository/"
            resp = self.session.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            else:
                click.echo(f"Failed to list repositories: {resp.status_code} {resp.text}")
                return None
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")
            return None

    def create_repository(self, name: str, project: Optional[str], private: bool = True, use_template: bool = True) -> bool:
        headers = self.get_headers()
        payload = {"name": name, "private": bool(private), "use_template": bool(use_template)}
        if project is not None:
            # if project looks like an int -> send project_id else project_name
            try:
                pid = int(project)
                payload["project_id"] = pid
            except Exception:
                payload["project_name"] = project
        try:
            url = f"{self.base_url}/repository/"
            resp = self.session.post(url, json=payload, headers=headers, timeout=15)
            if resp.status_code in (200, 201):
                data = resp.json()
                click.echo(f"Repository '{name}' created (id: {data.get('id')}, from_template: {data.get('from_template')})")
                return True
            else:
                click.echo(f"Failed to create repository: {resp.status_code} {resp.text}")
                return False
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")
            return False

    # ---------------- Admin helpers ----------------
    def ensure_admin(self):
        info = self.get_user_info()
        if not info:
            raise click.ClickException("Not authenticated. Please login first.")
        if not info.get("is_admin"):
            raise click.ClickException("Admin privileges required for this command.")
        return True

    # ---------------- Admin actions ----------------
    def adm_list_users(self):
        try:
            self.ensure_admin()
            headers = self.get_headers()
            resp = self.session.get(f"{self.base_url}/users", headers=headers)
            if resp.status_code == 200:
                users = resp.json()
                if not users:
                    click.echo("No users found")
                    return
                table = [[u.get("id"), u.get("username"), u.get("project"), u.get("is_admin")] for u in users]
                # sort descending by ID
                table.sort(key=lambda x: x[0], reverse=True)
                click.echo(tabulate(table, headers=["ID", "Username", "Project ID", "Admin"], tablefmt="presto"))
            else:
                click.echo(f"Error fetching users: {resp.status_code} {resp.text}")
        except click.ClickException as ce:
            click.echo(str(ce))
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")

    def adm_create_project(self, name: str):
        """Create a new project"""
        try:
            self.ensure_admin()
            headers = self.get_headers()
            data = {"name": name}
            url = f"{self.base_url}/project/"
            resp = self.session.post(url, json=data, headers=headers)
            if resp.status_code in (200, 201):
                payload = resp.json()
                click.echo(f"Project '{name}' created (id: {payload.get('id')})")
            else:
                click.echo(f"Failed to create project: {resp.status_code} {resp.text}")
        except click.ClickException as ce:
            click.echo(str(ce))
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")

    def adm_list_projects(self):
        """List projects via GET /project/ (admin only)"""
        try:
            self.ensure_admin()
            headers = self.get_headers()
            url = f"{self.base_url}/project/"
            resp = self.session.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                projects = resp.json()
                if not projects:
                    click.echo("No projects found")
                    return
                # projects expected to be list of {"id":..., "name":...}
                rows = [[p.get("id"), p.get("name")] for p in projects]
                rows.sort(key=lambda x: x[0] or 0, reverse=True)
                click.echo(tabulate(rows, headers=["ID", "Name"], tablefmt="presto"))
            else:
                click.echo(f"Failed to list projects: {resp.status_code} {resp.text}")
        except click.ClickException as ce:
            click.echo(str(ce))
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")

    def adm_create_user(self, username: str, password: str, project: str, email: str, is_admin: bool):
        try:
            self.ensure_admin()
            headers = self.get_headers()
            data = {
                "username": username,
                "password": password,
                "project": project,
                "email": email,
                "is_admin": bool(is_admin)
            }
            resp = self.session.post(f"{self.base_url}/users", json=data, headers=headers)
            if resp.status_code in (200, 201):
                payload = resp.json()
                click.echo(f"User '{username}' created (id: {payload.get('id')})")
            else:
                click.echo(f"Failed to create user: {resp.status_code} {resp.text}")
        except click.ClickException as ce:
            click.echo(str(ce))
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")

    def adm_change_password(self, user_id: int, new_password: str):
        try:
            self.ensure_admin()
            headers = self.get_headers()
            data = {"password": new_password}
            resp = self.session.put(f"{self.base_url}/users/{user_id}/password", json=data, headers=headers)
            if resp.status_code == 200:
                click.echo(f"Password updated for user id {user_id}")
            else:
                click.echo(f"Failed to update password: {resp.status_code} {resp.text}")
        except click.ClickException as ce:
            click.echo(str(ce))
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")

    # ---------------- Accept Image ----------------
    def accept_image(self, image_details_id: int, new_tag: Optional[str] = None):
        headers = self.get_headers()
        payload = {"new_tag": new_tag} if new_tag else {}
        try:
            url = f"{self.base_url}/images/accept/{image_details_id}"
            resp = self.session.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                data = resp.json()
                click.echo(f"Image queued for accept: ID {data.get('image_details_id')}, new_tag={data.get('new_tag')}")
            else:
                click.echo(f"Failed to queue image for accept: {resp.status_code} {resp.text}")
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")


# ---------------- CLI Root ----------------
@click.group()
@click.pass_context
def cli(ctx):
    """KubeFlow Dashboard CLI"""
    ctx.obj = DockerFlowCLI()


# ---------------- Auth & basic commands ----------------
@cli.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
@click.pass_context
def login(ctx, username, password):
    """Login to the system"""
    ctx.obj.login(username, password)


@cli.command()
@click.pass_context
def logout(ctx):
    """Logout"""
    ctx.obj.logout()


@cli.command()
@click.option('--url', prompt=True, help='New endpoint URL')
@click.pass_context
def set_endpoint(ctx, url):
    """Set and save API endpoint"""
    ctx.obj.set_endpoint(url)


@cli.command()
@click.pass_context
def status(ctx):
    """Show auth status and user info"""
    ctx.obj.status()


# ---------------- get group ----------------
@cli.group(invoke_without_command=True)
@click.pass_context
def get(ctx):
    """Get resources"""
    if ctx.invoked_subcommand is None:
        click.echo("   Use: kfc get <resource> [identifier]")
        click.echo("                                    ")
        click.echo("   resources:")
        click.echo("       - images/image/img - shows images that pass image test pipeline")
        click.echo("       - imagetestpipeline/itp - shows triggered image pipelines")
        click.echo("       - deployments/deployment/deploy - shows images that are deployed")
        click.echo("       - repo/repos/repositories - list repositories")
        return

# ---------------- get image (primary) ----------------
@get.command("image")
@click.argument("arg", required=False)
@click.pass_context
def get_image_cmd(ctx, arg):
    cli_instance: DockerFlowCLI = ctx.obj
    if not arg:
        groups = cli_instance.get_images()
        if not groups:
            click.echo("No images found")
            return
        table = [[g.get("image_name"), g.get("count")] for g in groups]
        click.echo(tabulate(table, headers=["Image Group", "Versions"], tablefmt="presto"))
        return

    if "/" in arg:
        parts = arg.split("/")
        if len(parts) != 2:
            click.echo("Invalid format, use <group>/<id>")
            return
        group, image_id = parts
        img = cli_instance.get_images(group, image_id)
        if img:
            if isinstance(img, list):
                for i in img:
                    print_image_details(i)
            else:
                print_image_details(img)
    else:
        images = cli_instance.get_images(group=arg)
        if not images:
            click.echo("No images found")
            return
        table = [[i.get("id"), i.get("image_tag"), i.get("deploy_status"), i.get("created_at")] for i in images]

        table.sort(key=lambda x: x[0], reverse=True)
        click.echo(tabulate(table, headers=["ID", "Tag", "Deploy", "Created"], tablefmt="presto"))


get.add_command(get_image_cmd, name="images")
get.add_command(get_image_cmd, name="img")


# ---------------- get imagetestpipeline ----------------

@get.command("imagetestpipeline")
@click.argument("arg", required=False)
@click.option("--raw", is_flag=True, default=False, help="Print raw JSON from API instead of formatted table")
@click.pass_context
def get_imagetestpipeline_cmd(ctx, arg, raw):
    """Show Image Test Pipeline (ITP)"""
    cli_instance: DockerFlowCLI = ctx.obj

    if not arg:
        # lista grup/deploymentów
        groups = cli_instance.get_image_test_pipeline()
        if not groups:
            click.echo("No ImageTestPipeline groups found")
            return
        try:
            table = [[g.get("repo_name") or g.get("repo"), g.get("count")] for g in groups]
            click.echo(tabulate(table, headers=["Repo", "Deployments"], tablefmt="presto"))
        except Exception:
            click.echo(json.dumps(groups, indent=2, ensure_ascii=False))
        return

    # argument ma format repo/deploy_id
    if "/" in arg:
        parts = arg.split("/")
        if len(parts) != 2:
            click.echo("Invalid format, use <repo>/<deploy_id>")
            return
        repo, deploy_id = parts
        details = cli_instance.get_image_test_pipeline(group=repo, deploy_id=deploy_id)
        if not details:
            click.echo("No details found")
            return

        if raw:
            click.echo(json.dumps(details, indent=2, ensure_ascii=False))
            return

        # ładne wyświetlenie szczegółów deploymentu i logów
        print_deployment_details(details)
    else:
        # lista deploymentów dla repo
        deploys = cli_instance.get_image_test_pipeline(group=arg)
        if not deploys:
            click.echo("No deploys found for repo")
            return
        rows = []
        for d in deploys:
            rows.append([
                d.get("id"),
                d.get("repo_name") or d.get("repo"),
                d.get("image_tag") or d.get("tag") or "",
                d.get("status") or "",
                d.get("timestamp") or d.get("deployed_at") or d.get("created_at") or ""
            ])
        rows.sort(key=lambda x: x[0], reverse=True)
        click.echo(tabulate(rows, headers=["ID", "Repo", "Tag", "Status", "Timestamp"], tablefmt="presto"))

# Aliasy
get.add_command(get_imagetestpipeline_cmd, name="itp")
get.add_command(get_imagetestpipeline_cmd, name="imagetest")
get.add_command(get_imagetestpipeline_cmd, name="testpipeline")

# ---------------- get deployment (primary) ----------------
@get.command("deployment")
@click.argument("arg", required=False)
@click.pass_context
def get_deployment_cmd(ctx, arg):
    cli_instance: DockerFlowCLI = ctx.obj
    deployments = cli_instance.get_deployments(repo=arg)
    if not deployments:
        click.echo(f"No deployments found{' for repo ' + arg if arg else ''}")
        return

    if arg:
        if isinstance(deployments, list):
            # sort descending by ID if 'id' is present
            deployments.sort(key=lambda d: d.get("id", 0), reverse=True)
            for d in deployments:
                print_deployment_details(d)
                click.echo("")
        elif isinstance(deployments, dict):
            print_deployment_details(deployments)
        else:
            click.echo(json.dumps(deployments, indent=2))
    else:
        rows = []
        for d in deployments:
            nodes_val = d.get("node") if d.get("node") is not None else ", ".join(d.get("nodes", [])) if isinstance(d.get("nodes", []), list) else str(d.get("nodes", ""))
            rows.append([d.get("repo_name"), d.get("tag") or d.get("image_tag"), nodes_val, d.get("status"), d.get("deployed_at")])
        click.echo(tabulate(rows, headers=["Repo", "Tag", "Nodes", "Status", "Deployed At"], tablefmt="presto"))


get.add_command(get_deployment_cmd, name="deploy")
get.add_command(get_deployment_cmd, name="deployments")


# ---------------- get repositories (new) ----------------
@get.command("repo")
@click.pass_context
def get_repo_cmd(ctx):
    """List repositories (admin sees all; regular user only their project)"""
    cli_instance: DockerFlowCLI = ctx.obj
    repos = cli_instance.get_repositories()
    if not repos:
        click.echo("No repositories found")
        return
    rows = [[r.get("id"), r.get("name"), r.get("project_id")] for r in repos]
    rows.sort(key=lambda x: x[0] or 0, reverse=True)
    click.echo(tabulate(rows, headers=["ID", "Name", "Project ID"], tablefmt="presto"))

# add aliases
get.add_command(get_repo_cmd, name="repos")
get.add_command(get_repo_cmd, name="repositories")


# ---------------- get imagetestpipeline ----------------
# (already added above)


# ---------------- Accept group ----------------
@cli.group(invoke_without_command=True)
@click.pass_context
def accept(ctx):
    if ctx.invoked_subcommand is None:
        click.echo("   Use: kfc accept image [identifier]")
        click.echo("                                    ")
        click.echo("       - [identifier] image id")
        click.echo("       - -v new tag if not set tag will be set incrimentaly e.g. v66")
        return


@accept.command("image")
@click.argument("image_details_id", type=int)
@click.option("--new-tag", type=str, help="Optional new tag for the image")
@click.pass_context
def accept_image_cmd(ctx, image_details_id, new_tag):
    ctx.obj.accept_image(image_details_id, new_tag)


# ---------------- Deploy group ----------------
@cli.group(invoke_without_command=True)
@click.pass_context
def deploy(ctx):
    if ctx.invoked_subcommand is None:
        click.echo("   Use: kfc deploy <resource>")
        click.echo("                                    ")
        click.echo("   resources:")
        click.echo("       - image - accepted images only can be deployed")
        return


@deploy.command("image")
@click.option("--project", "-p", type=str, help="Project name (required for deployment)")
@click.option("--repo", "-r", "repo_name", type=str, help="Repository / service name (required for deployment)")
@click.option("--tag", "-t", type=str, help="Image tag to deploy (required)")
@click.option("--host", "-H", "hosts", multiple=True, help="Host(s) to limit deployment to. Repeatable. If not provided, playbook will use inventory defaults.")
@click.pass_context
def deploy_image_cmd(ctx, project, repo_name, tag, hosts):
    """
    Deploy image on host/hosts.
    """
    invoked_any = any([project, repo_name, tag, hosts])
    if not invoked_any:
        click.echo(ctx.get_help())
        return

    if not project:
        click.echo("Project is required. Use --project or -p.")
        return
    if not repo_name:
        click.echo("Repository/service name is required. Use --repo or -r.")
        return
    if not tag:
        click.echo("Tag is required. Use --tag or -t.")
        return

    host_list = list(hosts) if hosts else None

    success = ctx.obj.deploy_image(project=project, repo_name=repo_name, tag=tag, hosts=host_list)
    if not success:
        return


# ---------------- Admin group ----------------
@cli.group()
@click.pass_context
def adm(ctx):
    try:
        ctx.obj.get_user_info()
    except click.ClickException:
        pass


@adm.command("list-users")
@click.pass_context
def adm_list_users_cmd(ctx):
    ctx.obj.adm_list_users()


@adm.command("create-user")
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.option("--project", default=None)
@click.option("--email", prompt=True)
@click.option("--is-admin", is_flag=True, default=False)
@click.pass_context
def adm_create_user_cmd(ctx, username, password, project, email, is_admin):
    if project is None:
        # FIX: assign the prompt result back to `project`
        project = click.prompt("Project")
    ctx.obj.adm_create_user(username, password, project, email, is_admin)


@adm.command("passwd")
@click.argument("user_id", type=int)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def adm_passwd_cmd(ctx, user_id, password):
    ctx.obj.adm_change_password(user_id, password)


@adm.command("create-project")
@click.option("--name", prompt=True, help="Name of the project to create")
@click.pass_context
def adm_create_project_cmd(ctx, name):
    """Create a new project"""
    ctx.obj.adm_create_project(name)

@adm.command("create-project")
@click.option("--name", prompt=True, help="Name of the project to create")
@click.pass_context
def adm_create_project_cmd(ctx, name):
    """Create a new project (admin only)"""
    ctx.obj.adm_create_project(name)


@adm.command("list-projects")
@click.pass_context
def adm_list_projects_cmd(ctx):
    """List all projects (admin only)"""
    ctx.obj.adm_list_projects()


# ---------------- create group (new) ----------------
@cli.group(invoke_without_command=True)
@click.pass_context
def create(ctx):
    """Create resources (e.g. repo)"""
    if ctx.invoked_subcommand is None:
        click.echo("   Use: kfc create <resource>")
        click.echo("                                    ")
        click.echo("   resources:")
        click.echo("       - repo/repository - create repository")
        return

@create.command("repo")
@click.option("--name", prompt=True, help="Repository name")
@click.option("--project", "-p", default=None, help="Project name or ID")
@click.option("--private/--public", default=True, help="Set repository visibility (default: private)")
@click.option("--use-template/--no-template", default=True, help="Create from server template 'template' owned by 'gitea_admin' (default: true)")
@click.pass_context
def create_repo_cmd(ctx, name, project, private, use_template):
    """
    Create repository. If --project is numeric it's treated as project_id, otherwise as project_name.
    """
    cli_instance: DockerFlowCLI = ctx.obj
    # if project not provided, prompt for it (match CLI conventions)
    if project is None:
        project = click.prompt("Project (name or id)")
    success = cli_instance.create_repository(name=name, project=project, private=private, use_template=use_template)
    if not success:
        ctx.exit(1)

# add aliases
create.add_command(create_repo_cmd, name="repos")
create.add_command(create_repo_cmd, name="repository")


# ---------------- Helper printers ----------------
def print_image_details(image: dict):
    rows = []
    simple_fields = ["id", "repo_name", "image_name", "image_tag", "build_status", "deploy_status", "created_at", "project","pipeline_image_test_id"]
    for f in simple_fields:
        rows.append([f, image.get(f, "N/A")])

    sec = image.get("security_checks")
    if sec and isinstance(sec, dict):
        for k, v in sec.items():
            rows.append([f"security_checks.{k}", v])

    vuln = image.get("vulnerabilities")
    if vuln and isinstance(vuln, dict):
        rows.append(["vulnerabilities.high", vuln.get("high", 0)])
        rows.append(["vulnerabilities.critical", vuln.get("critical", 0)])
        if "list" in vuln and isinstance(vuln["list"], list):
            rows.append(["vulnerabilities.list", "\n".join(vuln["list"])])

    click.echo(tabulate(rows, headers=["Property", "Value"], tablefmt="presto"))


def print_deployment_details(d: dict):
    """Wyświetla szczegóły deploymentu oraz logi z modelu ImageDeploy"""
    if isinstance(d, list):
        for item in d:
            print_deployment_details(item)
            click.echo("")
        return

    # 1. Podstawowe dane w tabeli (styl presto)
    rows = [
        ["id", d.get("id")],
        ["repo_name", d.get("repo_name") or d.get("repo")],
        ["image_tag", d.get("image_tag") or d.get("tag")],
        ["status", d.get("status")],
        ["project", d.get("project")],
        ["timestamp", d.get("timestamp") or d.get("deployed_at")],
        ["commit_author", d.get("commit_author")],
        ["commit_id", d.get("commit_id")]
    ]
    click.echo(tabulate(rows, tablefmt="presto"))

    # 2. Wyświetlanie logów zgodnie z modelem SQLAlchemy

    # --- failed_task_info ---
    failed_info = d.get("failed_task_info")
    if failed_info:
        click.echo("\n--- Failed Task Info ---")
        click.echo(failed_info)

    # --- last_playbook_lines ---
    playbook_logs = d.get("last_playbook_lines")
    if playbook_logs:
        click.echo("\n--- Last Playbook Lines ---")
        if isinstance(playbook_logs, list):
            for s in playbook_logs:
                click.echo(json.dumps(s, ensure_ascii=False, indent=2))
        else:
            click.echo(playbook_logs)

    # --- pod_log_lines ---
    pod_logs = d.get("pod_log_lines")
    if pod_logs:
        click.echo("\n--- Pod Log Lines ---")
        if isinstance(pod_logs, list):
            for s in pod_logs:
                click.echo(json.dumps(s, ensure_ascii=False, indent=2))
        else:
            click.echo(pod_logs)
# ---------------- Main ----------------
if __name__ == "__main__":
    cli()

