require 'java'
java_import 'burp.IBurpExtender'
java_import 'burp.IMessageEditorTab'
java_import 'burp.IMessageEditorTabFactory'
java_import 'burp.IParameter'

class BurpExtender
  include IBurpExtender, IMessageEditorTabFactory

  attr_accessor :callbacks, :helpers

  def registerExtenderCallbacks(callbacks)
    # keep a reference to our callbacks object
    @callbacks = callbacks

    # obtain an extension helpers object
    @helpers = callbacks.getHelpers

    # set our extension name
    callbacks.setExtensionName "Serialized input editor"

    # register ourselves as a message editor tab factory
    callbacks.registerMessageEditorTabFactory(self)

    return
  end

  #
  # implement IMessageEditorTabFactory
  #

  def createNewInstance(controller, editable)
    # create a new instance of our custom editor tab
    Base64InputTab.new self, controller, editable
  end
end

#
# class implementing IMessageEditorTab
#

class Base64InputTab
  include IMessageEditorTab

  def initialize(extender, controller, editable)
    @extender = extender
    @editable = editable

    # create an instance of Burp's text editor, to display our deserialized data
    @txtInput = extender.callbacks.createTextEditor
    @txtInput.setEditable editable
  end

  #
  # implement IMessageEditorTab
  #

  def getTabCaption()
      "Serialized input"
  end

  def getUiComponent()
      @txtInput.getComponent
  end

  def isEnabled(content, isRequest)
    # enable this tab for requests containing a data parameter
    isRequest and not @extender.helpers.getRequestParameter(content, "data").nil?
  end

  def setMessage(content, isRequest)
    if content.nil?
      # clear our display
      @txtInput.setText nil
      @txtInput.setEditable false
    else
      # retrieve the data parameter
      parameter = @extender.helpers.getRequestParameter(content, "data")

      # deserialize the parameter value
      @txtInput.setText @extender.helpers.base64Decode(@extender.helpers.urlDecode parameter.getValue)
      @txtInput.setEditable @editable
    end

    # remember the displayed content
    @currentMessage = content

    return
  end

  def getMessage()
    # determine whether the user modified the deserialized data
    if @txtInput.isTextModified
        # reserialize the data
        text = @txtInput.getText
        input = @extender.helpers.urlEncode @extender.helpers.base64Encode(text)

        # update the request with the new parameter value
        @extender.helpers.updateParameter @currentMessage, @extender.helpers.buildParameter("data", input, IParameter.PARAM_BODY)
    else
        @currentMessage
    end
  end

  def isModified()
    @txtInput.isTextModified
  end

  def getSelectedData()
    @txtInput.getSelectedText
  end
end
