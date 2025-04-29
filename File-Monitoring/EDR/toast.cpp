#include "toast.h"
#include <string>
#include <sstream>
#include <cstdlib>

void show_toast_notification(const std::string& title, const std::string& message) {
    std::stringstream psScript;
    psScript << "powershell -ExecutionPolicy Bypass -Command \""
        << "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
        << "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
        << "$template.SelectSingleNode('//text[@id=1]').InnerText = '" << title << "';"
        << "$template.SelectSingleNode('//text[@id=2]').InnerText = '" << message << "';"
        << "$toast = [Windows.UI.Notifications.ToastNotification]::new($template);"
        << "$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('MonitorApp');"
        << "$notifier.Show($toast)\"";

    system(psScript.str().c_str());
}
