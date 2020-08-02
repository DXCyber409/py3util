import subprocess
import sys

def sh(command, print_msg=True):
    p = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result = p.stdout.read().decode('utf-8')
    if print_msg:
        print(result)
    return result


def safe_index_of(str0, substr):
    try:
        return str0.index(substr)
    except ValueError:
        return -1


def get_launcher_activity(package_name):
    result = sh("adb shell dumpsys package %s" %
                (package_name), print_msg=False)
    if not result:
        return
    end_index = safe_index_of(result, "android.intent.category.LAUNCHER")
    if end_index >= 0:
        start_index = (end_index - 150) if end_index - 150 >= 0 else 0
        lines = result[start_index:end_index].split(' ')
        for line in lines:
            if package_name in line:
                return line

    start_index = safe_index_of(result, "android.intent.action.MAIN")
    if start_index >= 0:
        end_index = (start_index + 300) if (start_index +
                                            300 < len(result)) else len(result)
        lines = result[start_index:end_index].split(' ')
        key = "%s/" % (package_name)
        for line in lines:
            if key in line:
                return line
    return ''

if (len(sys.argv) <= 1):
    print('Usage: python app_lauch_path.py package_name')
    exit()
print(get_launcher_activity(sys.argv[1]))