package org.owasp.webgoat.asciidoc;

import org.asciidoctor.ast.ContentNode;
import org.asciidoctor.extension.InlineMacroProcessor;

import java.util.Map;

public class WebGoatTmpDirMacro extends InlineMacroProcessor {

    public WebGoatTmpDirMacro(String macroName) {
        super(macroName);
    }

    public WebGoatTmpDirMacro(String macroName, Map<String, Object> config) {
        super(macroName, config);
    }

    @Override
	public Object process(ContentNode contentNode, String target, Map<String, Object> attributes) {
        var env = EnvironmentExposure.getEnv().getProperty("webgoat.server.directory");

        //see https://discuss.asciidoctor.org/How-to-create-inline-macro-producing-HTML-In-AsciidoctorJ-td8313.html for why quoted is used
        return createPhraseNode(contentNode, "quoted", env);

    }
}
