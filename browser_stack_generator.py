from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import json
import requests

try:
    url = "https://www.browserstack.com/automate/browsers.json"
    r = requests.get(url, auth=('ezracaltum1', 'VGztEA9aMUo9G6pKfoVH'))
    parsed_json = json.loads(r.content)
    for line in parsed_json:
        desired_cap = {}
        print json.dumps(line)+"\n"
        desired_cap = json.loads(json.dumps(line).replace("\"device\": null,", ""))

        # desired_cap = {'os': 'Windows', 'os_version': 'xp', 'browser': 'IE', 'browser_version': '7.0' }

        driver = webdriver.Remote(
			command_executor='http://ezracaltum1:VGztEA9aMUo9G6pKfoVH@hub.browserstack.com:80/wd/hub',
                desired_capabilities=desired_cap)

        driver.get("http://ec2-54-188-193-163.us-west-2.compute.amazonaws.com/z/awt_generator/xhr.html")
        html_source = driver.page_source
        driver.get("http://ec2-54-188-193-163.us-west-2.compute.amazonaws.com/z/awt_generator/awt_get.php")
        html_source = driver.page_source
        driver.quit()
except KeyboardInterrupt:
    raise
except:
    print "error"
