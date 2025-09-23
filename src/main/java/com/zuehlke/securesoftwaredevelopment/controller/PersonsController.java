package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.Role;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.RoleRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.PermissionDeniedDataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.List;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository, RoleRepository roleRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model) {
        model.addAttribute("person", personRepository.get("" + id));
        model.addAttribute("username", userRepository.findUsername(id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        model.addAttribute("username", userRepository.findUsername(user.getId()));
        return "person";
    }

    private boolean isAdmin(User user){
        List<Role> roles = roleRepository.findByUserId(user.getId());
        for (Role role : roles) {
            if (role.getName().equals("ADMIN")) { return true; }
        }
        return false;
    }

    @DeleteMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        if ( isAdmin(user) || user.getId() == id) {
            personRepository.delete(id);
            userRepository.delete(id);
        } else{
            throw new AccessDeniedException("Access denied.");
        }

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person, String username, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        Person tmpPerson = personRepository.get("" + user.getId());
        boolean isAdmin = isAdmin(user);
        if (isAdmin|| tmpPerson.getId().equals(person.getId())) {
            personRepository.update(person);
            userRepository.updateUsername(Integer.parseInt(person.getId()), username);
        }
        else{
            throw new AccessDeniedException("Access denied.");
        }
        if (isAdmin)
            return "redirect:/persons/" + person.getId();
        else
            return "redirect:/myprofile";
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model, Authentication authentication) {
        model.addAttribute("persons", personRepository.getAll());
        model.addAttribute("currPerson", personRepository.get("" + ((User) authentication.getPrincipal()).getId()));
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    @ResponseBody
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}
