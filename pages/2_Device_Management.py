from __future__ import annotations
import json, os, urllib.error, urllib.request
from urllib.parse import urlparse
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Sentinel | Device Fleet",page_icon="◈",layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{--line:#263951;--muted:#91a5bc;--cyan:#5ce1ee}
html,body,[class*="css"]{font-family:'Manrope',sans-serif}
.stApp{background:radial-gradient(ellipse at 75% -10%,#17364b 0%,#0a1422 42%,#070c14 100%);color:#eaf2fb}
.block-container{max-width:1450px;padding-top:2rem;padding-bottom:3rem}
section[data-testid="stSidebar"]{background:#0a1320;border-right:1px solid #203149}
.eyebrow{color:#5ce1ee;font:500 10px 'DM Mono',monospace;letter-spacing:.2em;text-transform:uppercase}
.hero{padding:8px 0 22px;border-bottom:1px solid #22334a;margin-bottom:22px}
.hero h1{font-size:clamp(30px,4vw,44px);line-height:1.08;margin:8px 0;font-weight:800;letter-spacing:-.045em}
.hero p{color:#91a2b8;margin:0;font-size:14px}
.metric{background:linear-gradient(145deg,#14243a,#101a29);border:1px solid #293c55;border-radius:14px;padding:17px;min-height:108px}
.metric-label{color:#91a5bc;font:10px 'DM Mono',monospace;letter-spacing:.13em}
.metric-value{color:#f1f7ff;font-size:29px;font-weight:800;margin-top:9px}
</style>""",unsafe_allow_html=True)

def api_request(base_url,token,method,path,payload=None):
    parsed=urlparse(base_url)
    if parsed.scheme!="https" and not(parsed.scheme=="http" and parsed.hostname in {"localhost","127.0.0.1","::1","api"}):
        raise ValueError("Удалённый сервер должен использовать HTTPS. HTTP разрешён только для loopback и внутреннего Docker-сервиса api.")
    if not parsed.netloc: raise ValueError("Укажите корректный API URL.")
    data=json.dumps(payload).encode() if payload is not None else None
    headers={"Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    req=urllib.request.Request(base_url.rstrip("/") + path,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=8) as response: return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        try: detail=json.loads(exc.read().decode()).get("detail",str(exc))
        except Exception: detail=str(exc)
        raise RuntimeError(f"API HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError,TimeoutError,OSError) as exc: raise RuntimeError(f"Нет связи с Sentinel API: {exc}") from exc

with st.sidebar:
    st.markdown('<div class="eyebrow">◈ SENTINEL / CONTROL ROOM</div>',unsafe_allow_html=True)
    st.markdown("### Server")
    base_url=st.text_input("API URL",value=os.getenv("SENTINEL_API_URL","http://127.0.0.1:8000"))
    st.markdown("### Operator login")
    email=st.text_input("Email",key="operator_email")
    password=st.text_input("Password",type="password",key="operator_password")
    if st.button("Sign in",type="primary",use_container_width=True):
        try:
            auth=api_request(base_url,"","POST","/v1/auth/login",{"email":email,"password":password})
            st.session_state["sentinel_operator_token"]=auth["access_token"]
            st.session_state["sentinel_operator"]=auth["operator"]
            st.success("Signed in")
        except (ValueError,RuntimeError) as exc: st.error(str(exc))
    token=st.session_state.get("sentinel_operator_token","")
    operator=st.session_state.get("sentinel_operator",{})
    if token:
        st.caption(f'{operator.get("email")} · {operator.get("role")} · {operator.get("tenant_id")}')
        if st.button("Sign out",use_container_width=True):
            try: api_request(base_url,token,"POST","/v1/auth/logout")
            finally:
                st.session_state.pop("sentinel_operator_token",None)
                st.session_state.pop("sentinel_operator",None)
                st.rerun()
    st.caption("Use HTTPS for remote servers. Sessions expire after 12 hours.")

st.markdown("""<div class="hero"><div class="eyebrow">SENTINEL / ENDPOINT MANAGEMENT</div>
<h1>DEVICE FLEET <span style="color:#5ce1ee">//</span> INVENTORY</h1>
<p>Organization-scoped access · Endpoint enrollment · Audit trail</p></div>""",unsafe_allow_html=True)
if not token:
    st.info("Войдите под учётной записью оператора. Общий admin-токен больше не используется.")
    st.stop()
try:
    overview=api_request(base_url,token,"GET","/v1/overview")
    inventory=api_request(base_url,token,"GET","/v1/devices")
except (ValueError,RuntimeError) as exc:
    st.error(str(exc)); st.stop()

cards=[("DEVICES",overview["devices"]),("ACTIVE",overview["active_devices"]),
       ("REVOKED",overview["revoked_devices"]),("EVENTS",overview["total_events"])]
cols=st.columns(4)
for col,(label,value) in zip(cols,cards):
    with col: st.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value:,}</div></div>',unsafe_allow_html=True)

enroll_tab,inventory_tab,audit_tab,operators_tab,guide_tab=st.tabs(["＋ Enroll device","▦ Inventory","◷ Audit log","♙ Operators","ⓘ Setup"])
with enroll_tab:
    st.subheader("Register a Windows workstation")
    if operator.get("role") not in ("owner","admin"): st.info("Your role can view inventory but cannot enroll endpoints.")
    else:
        with st.form("enroll_device",clear_on_submit=True):
            name=st.text_input("Device name",placeholder="Office-PC-01")
            submitted=st.form_submit_button("Generate device credential",type="primary")
        if submitted:
            try:
                created=api_request(base_url,token,"POST","/v1/devices",{"name":name.strip()})
                st.success(f'{created["name"]} enrolled in {created["tenant_id"]}.')
                st.warning("Скопируйте секрет сейчас — сервер не сможет показать его повторно.")
                st.code(created["device_token"])
                st.code(f'$env:SENTINEL_DEVICE_TOKEN = "{created["device_token"]}"\npython -m sentinel.windows_sensor --output sentinel_endpoint_flows.csv --interval 10 --seconds 300 --server-url {base_url.rstrip("/")}',language="powershell")
            except (ValueError,RuntimeError) as exc: st.error(str(exc))
with inventory_tab:
    devices=inventory.get("devices",[])
    if not devices: st.info("No devices enrolled in this organization.")
    else:
        frame=pd.DataFrame(devices)
        frame["status"]=frame["revoked_at"].apply(lambda v:"REVOKED" if v else "ACTIVE")
        frame["last_seen"]=frame["last_seen"].fillna("Never connected")
        st.dataframe(frame[["name","tenant_id","status","event_count","last_seen","created_at","device_id"]],use_container_width=True,hide_index=True)
        active=frame[frame["revoked_at"].isna()]
        if not active.empty and operator.get("role") in ("owner","admin"):
            choices={f'{r["name"]} · {r["device_id"][:8]}':r["device_id"] for _,r in active.iterrows()}
            selected=st.selectbox("Device to revoke",list(choices))
            confirm=st.checkbox("I understand this immediately disables the device credential.")
            if st.button("Revoke device",disabled=not confirm):
                try:
                    api_request(base_url,token,"DELETE","/v1/devices/"+choices[selected])
                    st.success("Device credential revoked."); st.rerun()
                except (ValueError,RuntimeError) as exc: st.error(str(exc))
with audit_tab:
    if operator.get("role") not in ("owner","admin"): st.info("Audit log is available to organization administrators.")
    else:
        try:
            entries=api_request(base_url,token,"GET","/v1/audit")["entries"]
            st.dataframe(pd.DataFrame(entries),use_container_width=True,hide_index=True) if entries else st.info("No administrative actions recorded yet.")
        except (ValueError,RuntimeError) as exc: st.error(str(exc))

with operators_tab:
    st.subheader("Organization operators")
    if operator.get("role") != "owner":
        st.info("Only the organization owner can create or disable operator accounts.")
    else:
        with st.form("create_operator", clear_on_submit=True):
            new_email=st.text_input("Work email", key="new_operator_email")
            new_password=st.text_input("Temporary password (12+ characters)", type="password", key="new_operator_password")
            new_role=st.selectbox("Role", ["admin","analyst","viewer"], format_func=lambda x: {"admin":"Administrator","analyst":"Security analyst","viewer":"Read only"}[x])
            create_operator=st.form_submit_button("Create operator", type="primary")
        if create_operator:
            try:
                result=api_request(base_url,token,"POST","/v1/operators",{"email":new_email.strip(),"password":new_password,"role":new_role})
                st.success(f"Created {result['email']} ({result['role']}). Ask them to sign in with the temporary password.")
            except (ValueError,RuntimeError) as exc:
                st.error(str(exc))
        st.divider()
        try:
            operator_rows=api_request(base_url,token,"GET","/v1/operators").get("operators",[])
            if operator_rows:
                st.dataframe(pd.DataFrame(operator_rows),use_container_width=True,hide_index=True)
                active_ops=[x for x in operator_rows if not x.get("disabled_at") and x["operator_id"] != operator.get("operator_id")]
                if active_ops:
                    op_choices={f"{x['email']} · {x['role']}":x["operator_id"] for x in active_ops}
                    selected_op=st.selectbox("Account to disable",list(op_choices),key="disable_operator_choice")
                    confirm_op=st.checkbox("I confirm that this account must lose access immediately.",key="confirm_disable_operator")
                    if st.button("Disable operator",disabled=not confirm_op):
                        try:
                            api_request(base_url,token,"DELETE","/v1/operators/"+op_choices[selected_op])
                            st.success("Account disabled and active sessions revoked."); st.rerun()
                        except (ValueError,RuntimeError) as exc: st.error(str(exc))
            else:
                st.info("No operator accounts found.")
        except (ValueError,RuntimeError) as exc:
            st.error(str(exc))

with guide_tab:
    st.markdown("""
**First-time setup (server operator):**
1. Set `SENTINEL_BOOTSTRAP_TOKEN` to a unique random secret of at least 32 characters.
2. Start the API and call `POST /v1/auth/bootstrap` once with that header to create the first organization owner.
3. Sign in here with the owner's email and password.
4. The owner can create named operator accounts through `POST /v1/operators`; roles are owner, admin, analyst and viewer.
5. Enroll each endpoint to issue its individual device token.

Bootstrap is one-time and is not used for normal dashboard access. Operator sessions expire after 12 hours. The API remains an early MVP: add deployment hardening, rate limits, monitoring, backup/retention and independent security review before customer production use.
""")
st.caption("SENTINEL · Organization-scoped operator access · Individual endpoint credentials")
