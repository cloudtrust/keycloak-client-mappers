package org.keycloak.protocol.saml.mappers;

import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.ProtocolMapperModel;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

public class ScriptBasedMapperTest {

    private MockHelper mockHelper = new MockHelper();

    @Test
    public void testTransformAttributeStatement() throws IOException{
        String script = "var theUser = user; " +
                "var groups = user.getGroups(); " +
                "var result = ''; " +
                "for each (var group in groups) result = result + 'morph-' + group.getName() + ';';" +
                "result;";
        List<AttributeStatementType.ASTChoiceType> execResult = runMapper(script, true);
        assertEquals(1, execResult.size());
        assertEquals(1, execResult.get(0).getAttribute().getAttributeValue().size());
        assertTrue(execResult.get(0).getAttribute().getAttributeValue().get(0) instanceof String);
        String result = execResult.get(0).getAttribute().getAttributeValue().get(0).toString();
        assertTrue(result.contains("morph-group1;"));
        assertTrue(result.contains("morph-group2;"));
        assertTrue(result.contains("morph-group3;"));
        assertEquals("morph-group1;morph-group2;morph-group3;".length(), result.length());
    }

    @Test
    public void testTransformAttributeStatementListSingle() throws IOException {
        String script = "var theUser = user; " +
                "var groups = user.getGroups(); " +
                "var array = []; " +
                "for each (var group in groups) array.push('morph-' + group.getName());" +
                "var result = Java.to(array);" +
                "result;";
        List<AttributeStatementType.ASTChoiceType> execResult = runMapper(script, true);
        assertEquals(1, execResult.size());
        assertEquals(3, execResult.get(0).getAttribute().getAttributeValue().size());
        assertTrue(execResult.get(0).getAttribute().getAttributeValue().contains("morph-group1"));
        assertTrue(execResult.get(0).getAttribute().getAttributeValue().contains("morph-group2"));
        assertTrue(execResult.get(0).getAttribute().getAttributeValue().contains("morph-group3"));
    }

    @Test
    public void tetsTransformAttributeStatementListMultiple() throws IOException {
        String script = "var list = new java.util.ArrayList(); " +
                "for each (var group in user.getGroups()) list.add('morph-' + group.getName());" +
                "list;";
        List<AttributeStatementType.ASTChoiceType> execResult = runMapper(script, false);
        assertEquals(3, execResult.size());
        List<String> results = execResult.stream().map(x -> (String)x.getAttribute().getAttributeValue().get(0)).collect(Collectors.toList());
        assertTrue(results.contains("morph-group1"));
        assertTrue(results.contains("morph-group2"));
        assertTrue(results.contains("morph-group3"));
    }

    @Ignore
    @Test
    public void tetsTransformAttributeStatementShadowGroup() throws IOException {
        String script = "var theUser = user; " +
                "var HttpGet = Java.type('org.apache.http.client.methods.HttpGet');" +
                "var HttpClients = Java.type('org.apache.http.impl.client.HttpClients');" +
                "var EntityUtils = Java.type('org.apache.http.util.EntityUtils');" +
                "var StandardCharsets = Java.type('java.nio.charset.StandardCharsets');" +
                "var request = new HttpGet('http://localhost/shadowgroups/usg/' + theUser.getUsername() + '?applicationUrl=smip.dev.icrc.org&mobilityStatus=mobile&jobFunctionCode=000152');" +
                "request.addHeader('referer', 'http://test.com');" +
                "var client = HttpClients.createDefault();" +
                "var response = client.execute(request);" +
                "try {" +
                "   var jsonString = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);" +
                "   var obj = JSON.parse(jsonString);" +
                "   var array = obj.$values;" +
                "} finally {" +
                "   response.close();" +
                "   client.close();" +
                "}" +
                "var result = Java.to(array);" +
                "result;";
        List<AttributeStatementType.ASTChoiceType> execResult = runMapper(script, true);
        assertEquals(1, execResult.size());
        List<?> attributeValues = execResult.get(0).getAttribute().getAttributeValue();
        assertEquals(7, execResult.get(0).getAttribute().getAttributeValue().size());
        assertTrue(attributeValues.contains("alpha"));
        assertTrue(attributeValues.contains("bravo"));
        assertTrue(attributeValues.contains("charlie"));
        assertTrue(attributeValues.contains("delta"));
        assertTrue(attributeValues.contains(mockHelper.getUser().getUsername()));
    }

    private List<AttributeStatementType.ASTChoiceType> runMapper(String script, boolean singleAttribute) throws IOException {
        SAMLAttributeStatementMapper scriptMapper = new ScriptBasedMapper();
        ProtocolMapperModel attributeScript = ScriptBasedMapper.create("Trivial script mapper","morphedGroup", "basic", null, script, singleAttribute);
        attributeScript.setId(UUID.randomUUID().toString());
        mockHelper.initMocks();
        AttributeStatementType attributeStatement = new AttributeStatementType();
        scriptMapper.transformAttributeStatement(attributeStatement, attributeScript, mockHelper.getSession(), mockHelper.getUserSession(), mockHelper.getClientSession());
        return attributeStatement.getAttributes();
    }
}
