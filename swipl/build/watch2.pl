:- use_foreign_library('./src/test_cpp.so').

:- dynamic watched_file/2.

init_watch :-
    Files = ['myfile3.pl', 'myfile4.pl'],
    forall(member(F, Files),
           ( exists_file(F) ->
               time_file(F, T),
               consult_file(F, T)
           ; assertz(watched_file(F, 0))
           )),
    watch_files.

watch_files :-
    repeat,
    sleep(1),
    findall(File, watched_file(File, _), Files),
    forall(member(F, Files), maybe_consult(F)),
    fail.

maybe_consult(File) :-
    exists_file(File),
    time_file(File, NewTime),
    (   watched_file(File, OldTime),
        NewTime \= OldTime
    ->  consult_file(File, NewTime)
    ;   true
    ).
maybe_consult(File) :-
    \+ exists_file(File),
    format("Waiting for file to appear: ~w~n", [File]).

consult_file(File, Timestamp) :-
    format("Consulting file: ~w~n", [File]),
    catch(consult(File), E, print_message(error, E)),
    retractall(watched_file(File, _)),
    assertz(watched_file(File, Timestamp)).

