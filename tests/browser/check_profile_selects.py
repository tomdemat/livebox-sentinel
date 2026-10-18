"""Browser regression for profile choices and native filter stability.

Requires Playwright as a test-only tool and a disposable fixture preview at
SENTINEL_TEST_URL (default http://127.0.0.1:19224). Never point at production:
the fixture device profile is edited, then restored.
"""
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

BASE = os.environ.get("SENTINEL_TEST_URL", "http://127.0.0.1:19224")
if BASE != "http://127.0.0.1:19224":
    raise RuntimeError("Use the disposable local fixture preview only")
OUT = Path("/tmp/sentinel-safari-check")
OUT.mkdir(exist_ok=True)


def run(browser, configuration, name):
    context = browser.new_context(**configuration)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(BASE + "/login")
    page.locator("#loginUsername").fill("owner")
    page.locator("#loginPassword").fill("preview-only-password")
    page.locator("#loginSubmit").click()
    page.wait_for_url(BASE + "/")
    page.locator("#devices tr").first.wait_for()
    # Unchanged collections must preserve the original native option nodes.
    assert page.evaluate("""async () => {
      for (const id of ['deviceCategory','deviceLocation']) {
        const select=document.getElementById(id);
        const options=[...select.options];
        await refresh();
        if(!options.every((option,index)=>select.options[index]===option))return false;
      }
      return true;
    }""")
    # Incoming profile changes are deferred while the picker is being used.
    assert page.evaluate("""() => {
      const select=document.getElementById('deviceCategory');
      select.value='Ordinateur';
      select.focus();
      const options=[...select.options];
      allDevices.push({mac:'test-transient',name:'Test',category:'Catégorie arrivée pendant le choix'});
      updateFilterOptions('deviceCategory','category','Toutes les catégories');
      const stable=options.length===select.options.length&&options.every((option,index)=>select.options[index]===option);
      select.blur();
      const updated=[...select.options].some(option=>option.value==='Catégorie arrivée pendant le choix');
      const retained=select.value==='Ordinateur';
      allDevices.pop();
      resetDeviceFilters();
      return stable&&updated&&retained;
    }""")
    page.locator("#deviceCategory").select_option("Ordinateur")
    assert page.locator("#devices tr").count() == 1
    page.locator("#deviceLocation").select_option("Bureau")
    assert page.locator("#devices tr").count() == 1
    page.locator(".device-open").click()
    page.locator("#deviceDialog").wait_for(state="visible")
    assert page.locator("datalist").count() == 0
    assert page.locator("#profileCategoryChoice").input_value() == "value:Ordinateur"
    assert page.locator("#profileLocationChoice").input_value() == "value:Bureau"
    page.locator("#profileCategoryChoice").select_option("value:Objet connecté")
    page.locator("#profileLocationChoice").select_option("value:Salon")
    assert page.locator("#profileCategoryCustom").is_hidden()
    assert page.locator("#profileCategory").input_value() == "Objet connecté"
    page.locator("#deviceProfileForm button[type=submit]").click()
    page.wait_for_function("() => (document.getElementById('profileMessage').textContent==='Profil enregistré.')")
    # Changing a profile may remove it from the current filter; the open sheet stays usable.
    assert page.locator("#deviceDialog").is_visible()
    page.locator("#profileCategoryChoice").select_option("custom")
    page.locator("#profileCategory").fill("custom")
    page.locator("#profileLocationChoice").select_option("custom")
    page.locator("#profileLocation").fill("Atelier & terrasse")
    assert page.evaluate("""async () => {
      await refresh();
      return document.getElementById('profileCategory').value==='custom'&&document.getElementById('profileLocation').value==='Atelier & terrasse';
    }""")
    page.locator("#deviceProfileForm button[type=submit]").click()
    page.wait_for_function("() => (document.getElementById('profileMessage').textContent==='Profil enregistré.')")
    page.locator("#closeDevice").click()
    page.locator("#resetDeviceFilters").click()
    page.evaluate("selectDevice('aa:bb:cc:dd:ee:01')")
    assert page.locator("#profileCategoryChoice").input_value() == "value:custom"
    assert page.locator("#profileLocationChoice").input_value() == "value:Atelier & terrasse"
    assert page.locator("#profileCategoryCustom").is_hidden()
    assert page.locator("#profileLocationCustom").is_hidden()
    if configuration.get("is_mobile"):
        assert page.locator("#profileCategoryChoice").evaluate("el=>parseFloat(getComputedStyle(el).fontSize)>=16")
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    page.locator(".profile-section").screenshot(path=str(OUT / (name + ".png")))
    # Explicitly clearing both fields must still be supported.
    page.locator("#profileCategoryChoice").select_option("value:")
    page.locator("#profileLocationChoice").select_option("value:")
    assert page.locator("#profileCategory").input_value() == ""
    assert page.locator("#profileLocation").input_value() == ""
    # Restore the fixture for the next browser and leave no persistent changes.
    page.locator("#profileCategoryChoice").select_option("value:Ordinateur")
    page.locator("#profileLocationChoice").select_option("value:Bureau")
    page.locator("#deviceProfileForm button[type=submit]").click()
    page.wait_for_function("() => (document.getElementById('profileMessage').textContent==='Profil enregistré.')")
    assert not errors, errors
    context.close()
    return name


if __name__ == "__main__":
    with sync_playwright() as p:
        results = []
        with p.webkit.launch() as browser:
            results.append(run(browser, p.devices["iPhone 13"], "webkit-iphone"))
            results.append(run(browser, {"viewport": {"width": 1440, "height": 1000}}, "webkit-desktop"))
        with p.chromium.launch(executable_path="/opt/brave.com/brave/brave", args=["--no-sandbox"]) as browser:
            results.append(run(browser, p.devices["iPhone 13"], "chromium-mobile"))
        print(json.dumps({"passed": results, "profile_presets_custom_clear": "OK", "picker_options_stable_during_refresh": "OK", "screenshots": str(OUT)}))
