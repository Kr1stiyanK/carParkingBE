insert into user_roles (id, role)
values (1, 'ADMIN');
insert into user_roles (id, role)
values (2, 'USER');
insert into user_roles (id, role)
values (3, 'GUEST');

insert into users (id, email, name, password, role_id)
    value (1,'admin@mail.com','admin','admin',1);

insert into users (id, email, name, password, role_id)
    value (2,'guest@mail.com','guest','guest',3);


insert into parking_spaces (id, name)
values (1, 'Park Space 1'),
       (2, 'Park Space 2'),
       (3, 'Park Space 3'),
       (4, 'Park Space 4'),
       (5, 'Park Space 5'),
       (6, 'Park Space 6'),
       (7, 'Park Space 7'),
       (8, 'Park Space 8'),
       (9, 'Park Space 9'),
       (10, 'Park Space 10'),
       (11, 'Park Space 11'),
       (12, 'Park Space 12'),
       (13, 'Park Space 13'),
       (14, 'Park Space 14'),
       (15, 'Park Space 15'),
       (16, 'Park Space 16'),
       (17, 'Park Space 17'),
       (18, 'Park Space 18'),
       (19, 'Park Space 19'),
       (20, 'Park Space 20');
