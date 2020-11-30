<?php 
require_once("../../kernel/kernel.php");

//S'il n'y a aucune session c'est que le joueur n'est pas connecté alors on le redirige vers l'accueil
if (empty($_SESSION['account'])) { exit(header("Location: ../../modules/login/index.php")); }
//S'il y a actuellement un combat on redirige le joueur vers le module battle
if ($battleRow > 0) { exit(header("Location: ../../modules/battle/index.php")); }

require_once("../../html/header.php");
?>

<?php echo $accountPseudo ?><br />

<hr>

Adresse email : <?php echo $accountEmail ?><br />
Dernière connexion : <?php echo strftime('%d-%m-%Y - %H:%M:%S',strtotime($accountLastConnection)) ?><br />
Dernière action : <?php echo strftime('%d-%m-%Y - %H:%M:%S',strtotime($accountLastAction)) ?><br />
Accès : <?php echo $accountAccess ?><br />

<hr>

<form method="POST" action="changeEmail.php">
    <input type="hidden" class="btn btn-default form-control" name="token" value="<?php echo $_SESSION['token'] ?>">
    <input type="submit" name="changeEmail" class="btn btn-default form-control" value="Changer l'adresse Email"><br>
</form>

<?php


//On vérifie si le joueur à jamais crée sa question secrête
if ($accountSecretQuestion == "" && $accountSecretAnswer == "")
{
    ?>

    <form method="POST" action="addSecretQuestion.php">
        <input type="hidden" class="btn btn-default form-control" name="token" value="<?php echo $_SESSION['token'] ?>">
        <input type="submit" name="addSecretQuestion" class="btn btn-default form-control" value="Créer une question secrète"><br>
    </form>

    <?php
}
else
{
    ?>

    <form method="POST" action="changeSecretQuestion.php">
        <input type="hidden" class="btn btn-default form-control" name="token" value="<?php echo $_SESSION['token'] ?>">
        <input type="submit" name="changeSecretQuestion" class="btn btn-default form-control" value="Modifier la question secrète"><br>
    </form>

    <?php
}
?>

<form method="POST" action="../../modules/account/changePassword.php">
    <input type="hidden" class="btn btn-default form-control" name="token" value="<?php echo $_SESSION['token'] ?>">
    <input type="submit" name="changePassword" class="btn btn-default form-control" value="Changer le mot de passe"><br>
</form>

<?php require_once("../../html/footer.php"); ?>