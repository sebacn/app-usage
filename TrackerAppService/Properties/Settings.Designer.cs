﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace TrackerAppService.Properties {
    
    
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator", "17.13.0.0")]
    internal sealed partial class Settings : global::System.Configuration.ApplicationSettingsBase {
        
        private static Settings defaultInstance = ((Settings)(global::System.Configuration.ApplicationSettingsBase.Synchronized(new Settings())));
        
        public static Settings Default {
            get {
                return defaultInstance;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("sfsfsdfsf")]
        public string influxUrl {
            get {
                return ((string)(this["influxUrl"]));
            }
            set {
                this["influxUrl"] = value;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("")]
        public string influxToken {
            get {
                return ((string)(this["influxToken"]));
            }
            set {
                this["influxToken"] = value;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("sdfsdfsfs")]
        public string influxOrg {
            get {
                return ((string)(this["influxOrg"]));
            }
            set {
                this["influxOrg"] = value;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("dfdfdfdf")]
        public string influxBucket {
            get {
                return ((string)(this["influxBucket"]));
            }
            set {
                this["influxBucket"] = value;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute(@"<?xml version=""1.0"" encoding=""utf-16""?>
<ArrayOfString xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"">
  <string>notepad,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00</string>
  <string>chrome,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00</string>
  <string>word,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00,11:30:00</string>
</ArrayOfString>")]
        public global::System.Collections.Specialized.StringCollection appUsageLimits {
            get {
                return ((global::System.Collections.Specialized.StringCollection)(this["appUsageLimits"]));
            }
            set {
                this["appUsageLimits"] = value;
            }
        }
        
        [global::System.Configuration.UserScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("")]
        public string influxClientCertificate {
            get {
                return ((string)(this["influxClientCertificate"]));
            }
            set {
                this["influxClientCertificate"] = value;
            }
        }
    }
}
