
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
                table = [[u.get("id"), u.get("username"), u.get("project_id"), u.get("is_admin")] for u in users]
                # sort descending by ID
                table.sort(key=lambda x: x[0], reverse=True)
                click.echo(tabulate(table, headers=["ID", "Username", "Project ID", "Admin"], tablefmt="presto"))
            else:
                click.echo(f"Error fetching users: {resp.status_code} {resp.text}")
        except click.ClickException as ce:
            click.echo(str(ce))
        except requests.exceptions.RequestException as e:
            click.echo(f"Connection error: {e}")

    def adm_create_user(self, username: str, password: str, project_id: int, is_admin: bool):
        try:
            self.ensure_admin()
            headers = self.get_headers()
            data = {"username": username, "password": password, "project_id": int(project_id), "is_admin": bool(is_admin)}
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
@click.command("imagetestpipeline")
@click.argument("arg", required=False)
@click.option("--raw", is_flag=True, default=False, help="Print raw JSON from API instead of formatted table")
@click.pass_context
def get_imagetestpipeline_cmd(ctx, arg, raw):
    cli_instance: DockerFlowCLI = ctx.obj

    if not arg:
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

    if "/" in arg:
        parts = arg.split("/")
        if len(parts) != 2:
            click.echo("Invalid format, use <repo>/<id>")
            return
        repo, deploy_id = parts
        details = cli_instance.get_image_test_pipeline(group=repo, deploy_id=deploy_id)
        if not details:
            click.echo("No details found")
            return

        if raw:
            click.echo(json.dumps(details, indent=2, ensure_ascii=False))
            return

        if isinstance(details, dict):
            print_deployment_details(details)
        elif isinstance(details, list):
            for d in details:
                print_deployment_details(d)
                click.echo("")
        else:
            click.echo(json.dumps(details, indent=2, ensure_ascii=False))
    else:
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
        # sort descending by ID
        rows.sort(key=lambda x: x[0], reverse=True)
        click.echo(tabulate(rows, headers=["ID", "Repo", "Tag", "Status", "Timestamp"], tablefmt="presto"))


get.add_command(get_imagetestpipeline_cmd)
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
@click.option("--project-id", type=int, default=None)
@click.option("--is-admin", is_flag=True, default=False)
@click.pass_context
def adm_create_user_cmd(ctx, username, password, project_id, is_admin):
    if project_id is None:
        project_id = click.prompt("Project ID", type=int)
    ctx.obj.adm_create_user(username, password, project_id, is_admin)


@adm.command("passwd")
@click.argument("user_id", type=int)
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
@click.pass_context
def adm_passwd_cmd(ctx, user_id, password):
    ctx.obj.adm_change_password(user_id, password)


# ---------------- Helper printers ----------------
def print_image_details(image: dict):
    rows = []
    simple_fields = ["id", "repo_name", "image_name", "image_tag", "build_status", "deploy_status", "created_at", "project_id", "project","pipeline_image_test_id"]
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


def print_deployment_details(deploy: dict):
    nodes_field = deploy.get("node") if deploy.get("node") is not None else deploy.get("nodes", "")
    if isinstance(nodes_field, list):
        nodes_val = ", ".join(nodes_field)
    else:
        nodes_val = str(nodes_field) if nodes_field is not None else ""

    rows = [
        ["id", deploy.get("id")],
        ["project", deploy.get("project")],
        ["repo_name", deploy.get("repo_name") or deploy.get("repo")],
        ["image_tag", deploy.get("image_tag") or deploy.get("tag")],
        ["status", deploy.get("status")],
        ["timestamp", deploy.get("timestamp") or deploy.get("deployed_at") or deploy.get("created_at")],
        ["nodes", nodes_val],
        ["commit_id", deploy.get("commit_id")],
        ["commit_message", deploy.get("commit_message")],
        ["commit_author", deploy.get("commit_author")],
    ]

    rows = [[k, v] for k, v in rows if v not in (None, "", [], {})]

    click.echo(tabulate(rows, headers=["Property", "Value"], tablefmt="presto"))


# ---------------- Main ----------------
if __name__ == "__main__":
    cli()
