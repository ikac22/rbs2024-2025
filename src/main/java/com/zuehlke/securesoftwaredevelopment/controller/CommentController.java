package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.domain.Comment;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.CommentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpSession;
import java.nio.file.AccessDeniedException;

@Controller
public class CommentController {
    private static final Logger LOG = LoggerFactory.getLogger(CommentController.class);

    private CommentRepository commentRepository;

    public CommentController(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    @PostMapping(value = "/comments", consumes = "application/json")
    public ResponseEntity<Void> createComment(@RequestBody Comment comment, Authentication authentication,
                                              HttpSession session, @RequestParam("csrfToken") String csrfToken)
            throws AccessDeniedException
    {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if (!csrf.equals(csrfToken)) {
            throw new AccessDeniedException("Forbidden");
        }
        User user = (User) authentication.getPrincipal();
        comment.setUserId(user.getId());
        commentRepository.create(comment);

        return ResponseEntity.noContent().build();
    }
}
