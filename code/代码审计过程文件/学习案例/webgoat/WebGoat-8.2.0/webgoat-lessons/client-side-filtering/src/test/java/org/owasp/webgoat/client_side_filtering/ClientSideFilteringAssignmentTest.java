package org.owasp.webgoat.client_side_filtering;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.owasp.webgoat.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.when;
import static org.owasp.webgoat.client_side_filtering.ClientSideFilteringFreeAssignment.SUPER_COUPON_CODE;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

/**
 * @author nbaars
 * @since 5/2/17.
 */
@ExtendWith(SpringExtension.class)
public class ClientSideFilteringAssignmentTest extends LessonTest {

    @Autowired
    private ClientSideFiltering clientSideFiltering;

    @BeforeEach
    public void setup() {
        when(webSession.getCurrentLesson()).thenReturn(clientSideFiltering);
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    }

    @Test
    public void success() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/clientSideFiltering/getItForFree")
                .param("checkoutCode", SUPER_COUPON_CODE))
                .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
    }

    @Test
    public void wrongCouponCode() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/clientSideFiltering/getItForFree")
                .param("checkoutCode", "test"))
                .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))))
                .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
    }
}