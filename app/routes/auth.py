"""Sign-in, sign-out and the health check."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..security import authenticated, csrf_token, password_matches, validate_csrf
from ..web import render, require_auth

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if authenticated(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", error="")


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form(...)):
    validate_csrf(request, csrf)
    settings = request.app.state.settings
    # Compare both in constant time; a wrong username and a wrong password look the same.
    username_ok = password_matches(username.strip(), settings.admin_username)
    password_ok = password_matches(password, settings.admin_password)
    if username_ok and password_ok:
        request.session.clear()
        request.session["authenticated"] = True
        csrf_token(request)
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", error="Incorrect username or password", status_code=401)


@router.post("/logout", dependencies=[Depends(require_auth)])
def logout(request: Request, csrf: str = Form(...)):
    validate_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
