from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Serialized input editor")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return Base64InputTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class Base64InputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "Serialized input"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a data parameter
        return isRequest and not self._extender._helpers.getRequestParameter(content, "data") is None
        
    def setMessage(self, content, isRequest):
        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
        else:
            # retrieve the data parameter
            parameter = self._extender._helpers.getRequestParameter(content, "data")
            
            # deserialize the parameter value
            self._txtInput.setText(self._extender._helpers.base64Decode(self._extender._helpers.urlDecode(parameter.getValue())))
            self._txtInput.setEditable(self._editable)
        
        # remember the displayed content
        self._currentMessage = content
    
    def getMessage(self):
        # determine whether the user modified the deserialized data
        if self._txtInput.isTextModified():
            # reserialize the data
            text = self._txtInput.getText()
            input = self._extender._helpers.urlEncode(self._extender._helpers.base64Encode(text))
            
            # update the request with the new parameter value
            return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter("data", input, IParameter.PARAM_BODY))
            
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()
